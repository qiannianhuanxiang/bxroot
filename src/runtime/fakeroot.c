/*
 * fakeroot.c -- bxroot 的 fakeroot（uid/gid 伪装）层实现。
 *
 * 本文件分两段：
 *   §1–§5  纯逻辑：无 syscall、无 libc 依赖（除 malloc/string），可单元测试。
 *   §6–§7  钩子层：LD_PRELOAD 入口，全部通过 dlsym(RTLD_NEXT, ...) 解析。
 *
 * ★ 红线：本文件**没有**任何自研动态链接器 / ELF 符号解析器。
 *   所有「真实函数」一律走 dlsym(RTLD_NEXT, ...)，且**每次调用前都查 NULL**。
 *   这是 upstream issue #22（newfstatat 空指针 SIGSEGV）、#23/#24（自研
 *   重定位器）的直接对策。
 *
 * SPDX-License-Identifier: MIT
 */

#include "fakeroot.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>  /* makedev：把 stx_dev_major/minor 还原成 dev_t（F3） */
#include <unistd.h>   /* F_OK / R_OK / W_OK / X_OK（纯逻辑部分只用到这四个宏） */

/* ================================================================== */
/* §1  小工具                                                          */
/* ================================================================== */

/* unset id 哨兵：(uid_t)-1 / (gid_t)-1。不能用 -1 直接比，
 * 因为 uid_t 在 aarch64 上是 unsigned int。 */
#define FR_UNSET_UID ((uid_t)-1)
#define FR_UNSET_GID ((gid_t)-1)

static bool fr_uid_is_set(uid_t u) { return u != FR_UNSET_UID; }
static bool fr_gid_is_set(gid_t g) { return g != FR_UNSET_GID; }

/* mode 里我们关心的位：低 12 位（权限 + setuid/setgid/sticky）。 */
#define FR_MODE_BITS ((mode_t)07777)

static mode_t fr_mode_low(mode_t m) { return m & FR_MODE_BITS; }

/*
 * 把路径里的 "//" 折叠成 "/"、"a/./b" 里的 "." 去掉、结尾的 "/" 去掉。
 *
 * ⚠ 这**不是** realpath()：它不做符号链接解析、不查文件系统、不要求
 * 路径存在。目的只是让 `chown("f")` 与 `chown("./f")`、`chown("d//f")`
 * 落到同一个记账键上。真正的规范化（含 symlink）由钩子层在调用
 * 真实 stat 之后用 dev+ino 那一路兜底 —— 因为那时我们已经拿到了
 * 内核解析后的真实 inode。
 *
 * 相对路径原样保留（钩子层会先做 rootfs 前缀翻译，翻译不改变
 * 「相对 vs 绝对」的性质）。
 *
 * 返回写入 out 的字节数（不含 NUL）；out 空间不足时返回 FR_ENAMETOOLONG。
 */
static int fr_normalize_path(const char *in, char *out, size_t out_size)
{
    size_t oi = 0;
    size_t i = 0;
    bool   absolute;

    if (in == NULL || out == NULL || out_size == 0) {
        return FR_EINVAL;
    }

    absolute = (in[0] == '/');

    while (in[i] != '\0') {
        /* 折叠连续的 '/' */
        if (in[i] == '/') {
            while (in[i] == '/') {
                i++;
            }
            /* 只有在「原路径本来就是绝对的」或「前面已经写过东西且写的不是 '/'」
             * 时才补一个 '/'。否则 "./a" 会被悄悄写成 "/a"：相对路径被升级成
             * 绝对路径，记账键就和后续用绝对路径发起的查询对不上了。 */
            if (oi > 0) {
                if (out[oi - 1] != '/') {
                    if (oi + 1 >= out_size) {
                        return FR_ENAMETOOLONG;
                    }
                    out[oi++] = '/';
                }
            } else if (absolute) {
                if (oi + 1 >= out_size) {
                    return FR_ENAMETOOLONG;
                }
                out[oi++] = '/';
            }
            continue;
        }

        /* 去掉 "." 组件（前后必须是 '/' 或串首/串尾） */
        if (in[i] == '.') {
            bool at_start = (i == 0) || (in[i - 1] == '/');
            if (at_start && (in[i + 1] == '\0' || in[i + 1] == '/')) {
                i++;
                continue;
            }
        }

        if (oi + 1 >= out_size) {
            return FR_ENAMETOOLONG;
        }
        out[oi++] = in[i++];
    }

    /* 去掉结尾的 '/'（除非整个路径就是 "/"） */
    while (oi > 1 && out[oi - 1] == '/') {
        oi--;
    }

    out[oi] = '\0';
    return (int)oi;
}

/* 字符串哈希（FNV-1a 64）。比 djb2 在路径这类短字符串上分布更均匀。 */
static uint64_t fr_hash_bytes(const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    uint64_t h = 1469598103934665603ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/*
 * 把 fr_key 折成一个 64 位哈希。
 * 注意 dev/ino 走的是「按值」哈希而不是按字节 —— 结构体里有填充字节，
 * 按字节哈希会把未初始化的填充算进去，导致同一个键每次哈希不同。
 */
static uint64_t fr_key_hash(const fr_key *k)
{
    uint64_t h;

    switch (k->kind) {
    case FR_KEY_PATH:
        h = fr_hash_bytes(k->u.path, strlen(k->u.path));
        break;
    case FR_KEY_INODE:
        h  = fr_hash_bytes(&k->u.inode.dev, sizeof(k->u.inode.dev));
        h ^= fr_hash_bytes(&k->u.inode.ino, sizeof(k->u.inode.ino)) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        break;
    case FR_KEY_FD:
        h  = fr_hash_bytes(&k->u.fd, sizeof(k->u.fd));
        break;
    default:
        h = 0;
        break;
    }

    /* 混合 kind，确保不同类型的键即使内容相同也不互相干扰 */
    h ^= (uint64_t)k->kind * 0xff51afd7ed558ccdULL;
    return h;
}

/* ================================================================== */
/* §2  记账表：有界开放寻址哈希 + 墓碑 + 近似 LRU                        */
/* ================================================================== */

/*
 * 槽位状态：
 *   FR_SLOT_EMPTY 从未用过（探测到此即可断定「不存在」）
 *   FR_SLOT_LIVE  存活
 *   FR_SLOT_TOMB  删除后的墓碑（探测要继续，但插入可复用）
 */
typedef enum {
    FR_SLOT_EMPTY = 0,
    FR_SLOT_LIVE  = 1,
    FR_SLOT_TOMB  = 2
} fr_slot_state;

typedef struct {
    fr_slot_state state;
    fr_key        key;
    fr_record     rec;
    uint64_t      last_used;   /* 单调递增的逻辑时钟，越小越久未用 */
} fr_slot;

struct fakeroot_map {
    fr_slot *slots;
    size_t   cap;        /* 槽位数，恒为 2 的幂或 0 */
    size_t   mask;       /* cap - 1 */
    size_t   count;      /* LIVE 槽位数 */
    size_t   tombs;      /* TOMB 槽位数 */
    uint64_t clock;      /* 逻辑时钟，每次命中/插入 ++ */
    bool     disabled;   /* 关掉后插入 no-op、查询 ENOENT */
    bool     eviction;   /* 是否允许自动 LRU 淘汰 */
    /*
     * 可观测计数器（只增不减，fakeroot_map_clear 也不清零 —— 它统计的是
     * 「这张表一生做过几次全表重哈希」，是诊断量而不是状态量）。
     * 存在的理由：fr_map_compact 是 O(cap) 的隐式开销，从外部完全看不见。
     * 没有它，F2 那类「tombs 虚高 ⇒ 每次插入都重哈希」的退化只能靠
     * --wrap=calloc 这类链接期手法间接测出来，测试无法在库内自断言。
     */
    size_t   rehashes;   /* fr_map_compact 成功执行的次数 */
    size_t   compact_fail; /* fr_map_compact 因 ENOMEM/EFULL 失败的次数 */
};

/* 向上取整到 2 的幂；0 与 1 都返回 1。溢出返回 0。 */
static size_t fr_round_pow2(size_t v)
{
    size_t r = 1;

    if (v <= 1) {
        return 1;
    }
    while (r < v) {
        if (r > (SIZE_MAX / 2)) {
            return 0;   /* 溢出 */
        }
        r <<= 1;
    }
    return r;
}

fakeroot_map *fakeroot_map_create(size_t slots)
{
    fakeroot_map *m;
    size_t want;

    want = (slots == 0) ? (size_t)FR_MAP_DEFAULT_SLOTS : slots;
    if (want > (size_t)FR_MAP_MAX_SLOTS) {
        want = (size_t)FR_MAP_MAX_SLOTS;
    }
    want = fr_round_pow2(want);
    if (want == 0) {
        return NULL;
    }

    m = (fakeroot_map *)calloc(1, sizeof(*m));
    if (m == NULL) {
        return NULL;
    }

    m->slots = (fr_slot *)calloc(want, sizeof(*m->slots));
    if (m->slots == NULL) {
        free(m);
        return NULL;
    }

    m->cap      = want;
    m->mask     = want - 1;
    m->count    = 0;
    m->tombs    = 0;
    m->clock    = 0;
    m->disabled = false;
    m->eviction = true;
    return m;
}

/* 释放一个槽位占用的资源并置为墓碑。 */
static void fr_slot_release(fr_slot *s)
{
    if (s->state == FR_SLOT_LIVE) {
        fakeroot_key_dispose(&s->key);
    }
    s->state = FR_SLOT_TOMB;
    memset(&s->rec, 0, sizeof(s->rec));
}

void fakeroot_map_destroy(fakeroot_map *m)
{
    size_t i;

    if (m == NULL) {
        return;
    }
    if (m->slots != NULL) {
        for (i = 0; i < m->cap; i++) {
            if (m->slots[i].state == FR_SLOT_LIVE) {
                fakeroot_key_dispose(&m->slots[i].key);
            }
        }
        free(m->slots);
    }
    free(m);
}

void fakeroot_map_clear(fakeroot_map *m)
{
    size_t i;

    if (m == NULL || m->slots == NULL) {
        return;
    }
    for (i = 0; i < m->cap; i++) {
        if (m->slots[i].state == FR_SLOT_LIVE) {
            fakeroot_key_dispose(&m->slots[i].key);
        }
        m->slots[i].state = FR_SLOT_EMPTY;
        m->slots[i].last_used = 0;
        memset(&m->slots[i].rec, 0, sizeof(m->slots[i].rec));
    }
    m->count = 0;
    m->tombs = 0;
    m->clock = 0;
}

size_t fakeroot_map_count(const fakeroot_map *m)
{
    return (m == NULL) ? 0 : m->count;
}

size_t fakeroot_map_capacity(const fakeroot_map *m)
{
    return (m == NULL) ? 0 : m->cap;
}

void fakeroot_map_set_disabled(fakeroot_map *m, bool disabled)
{
    if (m != NULL) {
        m->disabled = disabled;
    }
}

bool fakeroot_map_is_disabled(const fakeroot_map *m)
{
    return (m == NULL) ? true : m->disabled;
}

void fakeroot_map_set_eviction(fakeroot_map *m, bool enabled)
{
    if (m != NULL) {
        m->eviction = enabled;
    }
}

bool fakeroot_map_eviction_enabled(const fakeroot_map *m)
{
    return (m == NULL) ? false : m->eviction;
}

size_t fakeroot_map_rehash_count(const fakeroot_map *m)
{
    return (m == NULL) ? 0 : m->rehashes;
}

size_t fakeroot_map_tomb_count(const fakeroot_map *m)
{
    return (m == NULL) ? 0 : m->tombs;
}

size_t fakeroot_map_compact_fail_count(const fakeroot_map *m)
{
    return (m == NULL) ? 0 : m->compact_fail;
}

/*
 * 自检：这张表的不变式是否成立。
 *   tomb 数 == 实际处于 TOMB 状态的槽位数
 *   live 数 == 实际处于 LIVE 状态的槽位数
 * 两者都是「计数器必须与槽位真实状态一致」的直接检查 ——
 * F2 正是这条不变式被破坏（tombs 只增不减）。
 * 表指针为 NULL 时返回 false（没有表就没有不变式可言）。
 */
bool fakeroot_map_check_invariants(const fakeroot_map *m)
{
    size_t i;
    size_t live = 0;
    size_t tomb = 0;

    if (m == NULL || m->slots == NULL) {
        return false;
    }
    for (i = 0; i < m->cap; i++) {
        if (m->slots[i].state == FR_SLOT_LIVE) {
            live++;
        } else if (m->slots[i].state == FR_SLOT_TOMB) {
            tomb++;
        }
    }
    return live == m->count && tomb == m->tombs;
}

int fakeroot_key_path(fr_key *out, const char *p)
{
    size_t len;
    char  *copy;

    if (out == NULL || p == NULL || p[0] == '\0') {
        return FR_EINVAL;
    }

    len = strlen(p);
    if (len >= (size_t)FR_PATH_MAX) {
        return FR_ENAMETOOLONG;
    }

    copy = (char *)malloc(len + 1);
    if (copy == NULL) {
        return FR_ENOMEM;
    }
    memcpy(copy, p, len + 1);

    out->kind   = FR_KEY_PATH;
    out->u.path = copy;
    return FR_OK;
}

int fakeroot_key_inode(fr_key *out, dev_t dev, ino_t ino)
{
    if (out == NULL) {
        return FR_EINVAL;
    }
    out->kind        = FR_KEY_INODE;
    out->u.inode.dev = dev;
    out->u.inode.ino = ino;
    return FR_OK;
}

int fakeroot_key_fd(fr_key *out, int fd)
{
    if (out == NULL) {
        return FR_EINVAL;
    }
    out->kind  = FR_KEY_FD;
    out->u.fd  = fd;
    return FR_OK;
}

void fakeroot_key_dispose(fr_key *k)
{
    if (k == NULL) {
        return;
    }
    if (k->kind == FR_KEY_PATH) {
        free(k->u.path);
    }
    memset(k, 0, sizeof(*k));
}

bool fakeroot_key_equal(const fr_key *a, const fr_key *b)
{
    if (a == NULL || b == NULL || a->kind != b->kind) {
        return false;
    }
    switch (a->kind) {
    case FR_KEY_PATH:
        if (a->u.path == NULL || b->u.path == NULL) {
            return a->u.path == b->u.path;
        }
        return strcmp(a->u.path, b->u.path) == 0;
    case FR_KEY_INODE:
        return a->u.inode.dev == b->u.inode.dev &&
               a->u.inode.ino == b->u.inode.ino;
    case FR_KEY_FD:
        return a->u.fd == b->u.fd;
    default:
        return false;
    }
}

/*
 * 探测。找到键则返回其下标；否则返回第一个可插入的下标
 * （优先复用墓碑），并把 *found 置成是否命中。
 * 表满且无墓碑可复用时返回 SIZE_MAX。
 */
static size_t fr_map_probe(const fakeroot_map *m, const fr_key *k, bool *found)
{
    size_t start;
    size_t i;

    *found = false;
    if (m->cap == 0) {
        return SIZE_MAX;
    }

    start = (size_t)(fr_key_hash(k) & (uint64_t)m->mask);

    for (i = 0; i < m->cap; i++) {
        size_t idx = (start + i) & m->mask;
        const fr_slot *s = &m->slots[idx];

        if (s->state == FR_SLOT_EMPTY) {
            return idx;                 /* 未命中；此槽可插入 */
        }
        if (s->state == FR_SLOT_LIVE && fakeroot_key_equal(&s->key, k)) {
            *found = true;
            return idx;
        }
    }

    /* 整圈扫完没有 EMPTY：表被 LIVE+TOMB 填满。
     * 这时如果还有墓碑，第一遍就能复用；没有则只能报满。 */
    for (i = 0; i < m->cap; i++) {
        size_t idx = (start + i) & m->mask;
        if (m->slots[idx].state == FR_SLOT_TOMB) {
            return idx;
        }
    }
    return SIZE_MAX;
}

/* 压缩：把所有 LIVE 条目 rehash 进一张同容量的新表，丢掉全部墓碑。 */
static int fr_map_compact(fakeroot_map *m)
{
    fr_slot *old_slots = m->slots;
    size_t   old_cap   = m->cap;
    fr_slot *new_slots;
    size_t   i;

    new_slots = (fr_slot *)calloc(m->cap, sizeof(*new_slots));
    if (new_slots == NULL) {
        m->compact_fail++;
        return FR_ENOMEM;
    }

    m->slots = new_slots;
    m->count = 0;
    m->tombs = 0;

    for (i = 0; i < old_cap; i++) {
        if (old_slots[i].state == FR_SLOT_LIVE) {
            bool found = false;
            size_t idx = fr_map_probe(m, &old_slots[i].key, &found);

            if (idx == SIZE_MAX) {
                /* 理论上不可达（同容量 + 无墓碑 ⇒ 必有空位）。
                 * 真发生了就回滚，保守报错。 */
                free(new_slots);
                m->slots = old_slots;
                m->count = 0;
                m->tombs = 0;
                for (size_t j = 0; j < old_cap; j++) {
                    if (old_slots[j].state == FR_SLOT_LIVE) {
                        m->count++;
                    } else if (old_slots[j].state == FR_SLOT_TOMB) {
                        m->tombs++;
                    }
                }
                m->compact_fail++;
                return FR_EFULL;
            }
            m->slots[idx].state     = FR_SLOT_LIVE;
            m->slots[idx].key       = old_slots[i].key;    /* 所有权转移 */
            m->slots[idx].rec       = old_slots[i].rec;
            m->slots[idx].last_used = old_slots[i].last_used;
            m->count++;
            /* 转移完成，避免下面的 free 重复释放 */
            old_slots[i].state = FR_SLOT_EMPTY;
            old_slots[i].key.kind = FR_KEY_FD;
            old_slots[i].key.u.fd = 0;
        }
    }

    free(old_slots);
    m->rehashes++;      /* 只统计**成功**的全表重哈希 */
    return FR_OK;
}

/*
 * 淘汰 n 个最久未使用的条目。
 * 实现：反复线性扫描找 last_used 最小的那个，删掉，重复 n 次。
 * O(n * cap)，但 n <= FR_MAP_EVICT_BATCH 且只在装载率超阈值时调用。
 */
size_t fakeroot_map_evict_lru(fakeroot_map *m, size_t n)
{
    size_t evicted = 0;

    if (m == NULL || m->slots == NULL || m->cap == 0) {
        return 0;
    }
    if (m->count == 0) {
        return 0;
    }
    if (n > m->count) {
        n = m->count;
    }

    while (evicted < n) {
        size_t   best = SIZE_MAX;
        uint64_t best_age = UINT64_MAX;
        size_t   i;

        for (i = 0; i < m->cap; i++) {
            if (m->slots[i].state != FR_SLOT_LIVE) {
                continue;
            }
            if (m->slots[i].last_used < best_age) {
                best_age = m->slots[i].last_used;
                best = i;
            }
        }
        if (best == SIZE_MAX) {
            break;
        }

        fr_slot_release(&m->slots[best]);
        m->count--;
        m->tombs++;
        evicted++;
    }

    return evicted;
}

/* 装载率是否已经到阈值。 */
static bool fr_map_overloaded(const fakeroot_map *m)
{
    /* 用「LIVE + TOMB」而不是「LIVE」来判断：墓碑同样会拉长探测链。 */
    size_t used = m->count + m->tombs;
    return (used * 100u) >= (m->cap * (size_t)FR_MAP_LOAD_PERCENT);
}

int fakeroot_map_put(fakeroot_map *m, fr_key k, const fr_record *rec)
{
    bool   found = false;
    size_t idx;

    if (m == NULL || m->slots == NULL || rec == NULL) {
        fakeroot_key_dispose(&k);
        return FR_EINVAL;
    }
    if (m->disabled) {
        /* 降级模式：不记账，但按约定接管键的所有权 */
        fakeroot_key_dispose(&k);
        return FR_OK;
    }

    /* 墓碑太多先压实；装载率太高先淘汰。顺序很重要：
     * 先压实可以把「被墓碑占满」误判成「真满」的情况纠正过来。 */
    if (m->tombs > (m->cap / 4u)) {
        int rc = fr_map_compact(m);
        if (rc != FR_OK) {
            fakeroot_key_dispose(&k);
            return rc;
        }
    }

    if (fr_map_overloaded(m) && m->eviction) {
        (void)fakeroot_map_evict_lru(m, (size_t)FR_MAP_EVICT_BATCH);
    }

    idx = fr_map_probe(m, &k, &found);
    if (idx == SIZE_MAX) {
        fakeroot_key_dispose(&k);
        return FR_EFULL;
    }

    m->clock++;
    if (found) {
        /* 覆盖：释放旧键，换成新键 */
        fakeroot_key_dispose(&m->slots[idx].key);
        m->slots[idx].key       = k;   /* 所有权转移 */
        m->slots[idx].rec       = *rec;
        m->slots[idx].last_used = m->clock;
        return FR_OK;
    }

    /* ⚠ 复用墓碑槽位时必须把 tombs 计回来。
     * fr_map_probe 有**两条**返回墓碑槽位的路径（EMPTY 未命中分支之前的
     * 第一遍扫描不会返回 TOMB，但「整圈无 EMPTY」时的第二遍扫描会返回
     * 第一个 TOMB），命中覆盖分支（found == true）只会拿到 LIVE 槽，
     * 所以这里是唯一的复用点 —— 但判定必须基于**槽位当前状态**，
     * 而不是基于「probe 走了哪条路」：这样无论将来 probe 怎么改，
     * tombs 都不会漂。
     *
     * 不修的话 tombs 只增不减 → fr_map_overloaded()（用 count + tombs 判）
     * 与压实阈值（tombs > cap/4）**永久为真** → 此后每次插入都做一次
     * 全表重哈希。 */
    if (m->slots[idx].state == FR_SLOT_TOMB) {
        m->tombs--;
    }
    m->slots[idx].state     = FR_SLOT_LIVE;
    m->slots[idx].key       = k;       /* 所有权转移 */
    m->slots[idx].rec       = *rec;
    m->slots[idx].last_used = m->clock;
    m->count++;
    return FR_OK;
}

int fakeroot_map_get(fakeroot_map *m, const fr_key *k, fr_record *out)
{
    bool   found = false;
    size_t idx;

    if (m == NULL || m->slots == NULL || k == NULL) {
        return FR_EINVAL;
    }
    if (m->disabled) {
        return FR_ENOENT;
    }

    idx = fr_map_probe(m, k, &found);
    if (!found || idx == SIZE_MAX) {
        return FR_ENOENT;
    }

    m->clock++;
    m->slots[idx].last_used = m->clock;
    if (out != NULL) {
        *out = m->slots[idx].rec;
    }
    return FR_OK;
}

bool fakeroot_map_has(fakeroot_map *m, const fr_key *k)
{
    return fakeroot_map_get(m, k, NULL) == FR_OK;
}

int fakeroot_map_remove(fakeroot_map *m, const fr_key *k)
{
    bool   found = false;
    size_t idx;

    if (m == NULL || m->slots == NULL || k == NULL) {
        return FR_EINVAL;
    }
    if (m->disabled) {
        return FR_ENOENT;
    }

    idx = fr_map_probe(m, k, &found);
    if (!found || idx == SIZE_MAX) {
        return FR_ENOENT;
    }

    fr_slot_release(&m->slots[idx]);
    m->count--;
    m->tombs++;
    return FR_OK;
}

/* ================================================================== */
/* §3  记账便捷封装                                                     */
/* ================================================================== */

/* 把两条 record 合并：只覆盖 faked 为真的字段。 */
static void fr_record_merge(fr_record *dst, const fr_record *src)
{
    if (src->uid_faked) {
        dst->uid = src->uid;
        dst->uid_faked = true;
    }
    if (src->gid_faked) {
        dst->gid = src->gid;
        dst->gid_faked = true;
    }
    if (src->mode_faked) {
        dst->mode = src->mode;
        dst->mode_faked = true;
    }
}

/*
 * 内部：读-改-写一条记录。
 * 这样 chown 之后再 chmod 不会把之前记的属主冲掉，反之亦然。
 */
static int fr_map_update(fakeroot_map *m, fr_key k, const fr_record *delta)
{
    fr_record cur;
    bool      found = false;
    size_t    idx;

    if (m == NULL || m->slots == NULL || delta == NULL) {
        fakeroot_key_dispose(&k);
        return FR_EINVAL;
    }
    if (m->disabled) {
        fakeroot_key_dispose(&k);
        return FR_OK;
    }

    idx = fr_map_probe(m, &k, &found);
    if (found && idx != SIZE_MAX) {
        fr_record_merge(&m->slots[idx].rec, delta);
        m->clock++;
        m->slots[idx].last_used = m->clock;
        fakeroot_key_dispose(&k);
        return FR_OK;
    }

    cur.uid        = fr_uid_is_set(delta->uid) ? delta->uid : (uid_t)0;
    cur.gid        = fr_gid_is_set(delta->gid) ? delta->gid : (gid_t)0;
    cur.mode       = delta->mode;
    cur.uid_faked  = delta->uid_faked;
    cur.gid_faked  = delta->gid_faked;
    cur.mode_faked = delta->mode_faked;
    return fakeroot_map_put(m, k, &cur);
}

/* 把一条增量同时写进 by_path（可选）与 by_inode（可选）。 */
static int fr_record_both(fakeroot_state *fs, const char *norm_path,
                          bool have_inode, dev_t dev, ino_t ino,
                          const fr_record *delta)
{
    int rc = FR_OK;

    if (fs == NULL || fs->records_disabled) {
        return FR_OK;
    }

    if (norm_path != NULL && fs->by_path != NULL) {
        fr_key k;
        int    kr = fakeroot_key_path(&k, norm_path);
        if (kr != FR_OK) {
            rc = kr;
        } else {
            int r2 = fr_map_update(fs->by_path, k, delta);
            if (r2 != FR_OK) {
                rc = r2;
            }
        }
    }

    if (have_inode && fs->by_inode != NULL) {
        fr_key k;
        int    kr = fakeroot_key_inode(&k, dev, ino);
        if (kr == FR_OK) {
            int r2 = fr_map_update(fs->by_inode, k, delta);
            if (r2 != FR_OK && rc == FR_OK) {
                rc = r2;
            }
        } else if (rc == FR_OK) {
            rc = kr;
        }
    }

    return rc;
}

/* 把路径归一化进栈缓冲。太长则返回 FR_ENAMETOOLONG。 */
static int fr_norm_into(const char *p, char *buf, size_t buf_size)
{
    return fr_normalize_path(p, buf, buf_size);
}

static int fr_make_owner_delta(fr_record *d, uid_t uid, gid_t gid)
{
    memset(d, 0, sizeof(*d));
    d->uid       = uid;
    d->gid       = gid;
    d->uid_faked = fr_uid_is_set(uid);
    d->gid_faked = fr_gid_is_set(gid);
    return FR_OK;
}

static int fr_make_mode_delta(fr_record *d, mode_t mode)
{
    memset(d, 0, sizeof(*d));
    d->mode       = fr_mode_low(mode);
    d->mode_faked = true;
    return FR_OK;
}

int fakeroot_record_owner_path(fakeroot_state *fs, const char *p,
                               uid_t uid, gid_t gid)
{
    char      buf[FR_PATH_MAX];
    fr_record d;
    int       rc;

    if (fs == NULL) {
        return FR_EINVAL;
    }
    if (p == NULL) {
        return FR_EINVAL;
    }

    rc = fr_norm_into(p, buf, sizeof(buf));
    if (rc < 0) {
        return rc;
    }

    (void)fr_make_owner_delta(&d, uid, gid);
    return fr_record_both(fs, buf, false, (dev_t)0, (ino_t)0, &d);
}

int fakeroot_record_owner_inode(fakeroot_state *fs, dev_t dev, ino_t ino,
                                uid_t uid, gid_t gid)
{
    fr_record d;

    if (fs == NULL) {
        return FR_EINVAL;
    }
    (void)fr_make_owner_delta(&d, uid, gid);
    return fr_record_both(fs, NULL, true, dev, ino, &d);
}

int fakeroot_record_owner_fd(fakeroot_state *fs, int fd,
                             uid_t uid, gid_t gid)
{
    fr_record d;
    fr_key    k;

    if (fs == NULL || fd < 0 || fs->records_disabled) {
        return FR_EINVAL;
    }
    (void)fr_make_owner_delta(&d, uid, gid);

    if (fs->by_path == NULL) {
        return FR_OK;
    }
    if (fakeroot_key_fd(&k, fd) != FR_OK) {
        return FR_EINVAL;
    }
    return fr_map_update(fs->by_path, k, &d);
}

int fakeroot_record_mode_path(fakeroot_state *fs, const char *p, mode_t mode)
{
    char      buf[FR_PATH_MAX];
    fr_record d;
    int       rc;

    if (fs == NULL || p == NULL) {
        return FR_EINVAL;
    }
    rc = fr_norm_into(p, buf, sizeof(buf));
    if (rc < 0) {
        return rc;
    }
    (void)fr_make_mode_delta(&d, mode);
    return fr_record_both(fs, buf, false, (dev_t)0, (ino_t)0, &d);
}

int fakeroot_record_mode_inode(fakeroot_state *fs, dev_t dev, ino_t ino,
                               mode_t mode)
{
    fr_record d;

    if (fs == NULL) {
        return FR_EINVAL;
    }
    (void)fr_make_mode_delta(&d, mode);
    return fr_record_both(fs, NULL, true, dev, ino, &d);
}

int fakeroot_record_mode_fd(fakeroot_state *fs, int fd, mode_t mode)
{
    fr_record d;
    fr_key    k;

    if (fs == NULL || fd < 0 || fs->records_disabled) {
        return FR_EINVAL;
    }
    (void)fr_make_mode_delta(&d, mode);

    if (fs->by_path == NULL) {
        return FR_OK;
    }
    if (fakeroot_key_fd(&k, fd) != FR_OK) {
        return FR_EINVAL;
    }
    return fr_map_update(fs->by_path, k, &d);
}

int fakeroot_lookup(fakeroot_state *fs, const char *p,
                    dev_t dev, ino_t ino, fr_record *out)
{
    fr_record acc;
    bool      any = false;

    if (fs == NULL || fs->records_disabled || out == NULL) {
        return FR_ENOENT;
    }

    memset(&acc, 0, sizeof(acc));

    /* 先查 inode：它不受 rename / 相对路径写法影响，最可靠。 */
    if (fs->by_inode != NULL && (dev != (dev_t)0 || ino != (ino_t)0)) {
        fr_key k;
        fr_record r;
        if (fakeroot_key_inode(&k, dev, ino) == FR_OK &&
            fakeroot_map_get(fs->by_inode, &k, &r) == FR_OK) {
            fr_record_merge(&acc, &r);
            any = true;
        }
    }

    if (p != NULL && fs->by_path != NULL) {
        char buf[FR_PATH_MAX];
        if (fr_norm_into(p, buf, sizeof(buf)) >= 0) {
            fr_key k;
            fr_record r;
            if (fakeroot_key_path(&k, buf) == FR_OK) {
                if (fakeroot_map_get(fs->by_path, &k, &r) == FR_OK) {
                    fr_record_merge(&acc, &r);
                    any = true;
                }
                fakeroot_key_dispose(&k);
            }
        }
    }

    if (!any) {
        return FR_ENOENT;
    }
    *out = acc;
    return FR_OK;
}

int fakeroot_lookup_fd(fakeroot_state *fs, int fd, fr_record *out)
{
    fr_key k;

    if (fs == NULL || fs->records_disabled || out == NULL || fd < 0) {
        return FR_ENOENT;
    }
    if (fs->by_path == NULL) {
        return FR_ENOENT;
    }
    if (fakeroot_key_fd(&k, fd) != FR_OK) {
        return FR_ENOENT;
    }
    if (fakeroot_map_get(fs->by_path, &k, out) != FR_OK) {
        return FR_ENOENT;
    }
    return FR_OK;
}

int fakeroot_forget_path(fakeroot_state *fs, const char *p)
{
    char buf[FR_PATH_MAX];
    fr_key k;
    int    rc;

    if (fs == NULL || p == NULL || fs->records_disabled) {
        return FR_EINVAL;
    }
    if (fs->by_path == NULL) {
        return FR_ENOENT;
    }
    if (fr_norm_into(p, buf, sizeof(buf)) < 0) {
        return FR_ENAMETOOLONG;
    }
    rc = fakeroot_key_path(&k, buf);
    if (rc != FR_OK) {
        return rc;
    }
    /* ⚠ 所有权：k 由 fakeroot_key_path 深拷贝而来（malloc），所有权在调用方。
     * fakeroot_map_remove 与 put 不同 —— 它**不接管** k，只释放表内那份键
     * （fr_slot_release 释放的是 m->slots[idx].key，不是这里的 k）。
     * 所以命中与未命中两条路径都必须由我们 dispose，否则每次调用漏一份
     * 路径副本（命中时漏 1 份、未命中时也漏 1 份）。
     * 注意不能先 dispose 再 remove：remove 还要用 k 去探测。 */
    {
        int rc2 = fakeroot_map_remove(fs->by_path, &k);
        fakeroot_key_dispose(&k);
        return rc2;
    }
}

int fakeroot_record_create_path(fakeroot_state *fs, const char *p, mode_t mode,
                                uid_t uid, gid_t gid)
{
    char      buf[FR_PATH_MAX];
    fr_record d;
    int       rc;

    if (fs == NULL || p == NULL) {
        return FR_EINVAL;
    }
    rc = fr_norm_into(p, buf, sizeof(buf));
    if (rc < 0) {
        return rc;
    }

    memset(&d, 0, sizeof(d));
    d.mode       = fr_mode_low(mode);
    d.mode_faked = true;
    if (fr_uid_is_set(uid)) {
        d.uid       = uid;
        d.uid_faked = true;
    }
    if (fr_gid_is_set(gid)) {
        d.gid       = gid;
        d.gid_faked = true;
    }

    return fr_record_both(fs, buf, false, (dev_t)0, (ino_t)0, &d);
}

int fakeroot_forget_inode(fakeroot_state *fs, dev_t dev, ino_t ino)
{
    fr_key k;

    if (fs == NULL || fs->records_disabled) {
        return FR_EINVAL;
    }
    if (fs->by_inode == NULL) {
        return FR_ENOENT;
    }
    if (fakeroot_key_inode(&k, dev, ino) != FR_OK) {
        return FR_EINVAL;
    }
    return fakeroot_map_remove(fs->by_inode, &k);
}

/* ================================================================== */
/* §4  stat 结果补丁（纯逻辑）                                          */
/* ================================================================== */

/*
 * 三级决策，对 stat/stat64/statx 共用：
 *   返回 true  ⇒ 用 *out 覆盖
 * 记账命中优先，其次启发式。
 */
static bool fr_decide_ids(fakeroot_state *fs, const fr_record *rec,
                          bool have_rec, uid_t real_uid, gid_t real_gid,
                          uid_t cur_uid, gid_t cur_gid,
                          uid_t *out_uid, gid_t *out_gid)
{
    bool changed = false;

    *out_uid = cur_uid;
    *out_gid = cur_gid;

    /* 规则 1：记账命中 */
    if (have_rec && rec != NULL) {
        if (rec->uid_faked) {
            *out_uid = rec->uid;
            changed = true;
        }
        if (rec->gid_faked) {
            *out_gid = rec->gid;
            changed = true;
        }
        if (changed) {
            return true;
        }
        /* 记账里只有 mode，属主还得走启发式 —— 继续往下。 */
    }

    if (fs == NULL || !fs->enabled) {
        return changed;
    }

    /* 规则 2：启发式 */
    switch (fs->heuristic) {
    case FR_HEURISTIC_OFF:
        break;

    case FR_HEURISTIC_OWNER:
        if (cur_uid == real_uid) {
            *out_uid = fs->euid;
            changed = true;
        }
        if (cur_gid == real_gid) {
            *out_gid = fs->egid;
            changed = true;
        }
        break;

    case FR_HEURISTIC_ALL:
        *out_uid = fs->euid;
        *out_gid = fs->egid;
        changed = true;
        break;

    default:
        break;
    }

    return changed;
}

/*
 * mode 合成，逐字照抄 proot stat.c:125：
 *     st_mode = rec.mode | (内核 st_mode & (S_IFMT | 07000))
 * 也就是「权限位取记账，文件类型 + setuid/setgid/sticky 取内核」。
 */
static mode_t fr_compose_mode(mode_t kernel_mode, mode_t rec_mode)
{
    return (mode_t)(fr_mode_low(rec_mode) |
                    (kernel_mode & (mode_t)(S_IFMT | 07000)));
}

void fakeroot_patch_stat_ex(struct stat *st, fakeroot_state *fs,
                            const fr_record *rec, int fd)
{
    fr_record local;
    bool      have_rec = false;
    uid_t     uid;
    gid_t     gid;

    if (st == NULL || fs == NULL || !fs->enabled) {
        return;
    }

    /* 调用方没给记录 ⇒ 自己按 dev+ino / fd 查一次。
     * 注意 patch_* 号称「纯函数」：这里的查询只碰内存表，不碰内核。 */
    if (rec != NULL) {
        local    = *rec;
        have_rec = true;
    } else {
        if (fakeroot_lookup(fs, NULL, st->st_dev, st->st_ino, &local) == FR_OK) {
            have_rec = true;
        } else if (fd >= 0 &&
                   fakeroot_lookup_fd(fs, fd, &local) == FR_OK) {
            have_rec = true;
        }
    }

    if (fr_decide_ids(fs, &local, have_rec, fs->real_uid, fs->real_gid,
                      st->st_uid, st->st_gid, &uid, &gid)) {
        st->st_uid = uid;
        st->st_gid = gid;
    }

    if (have_rec && local.mode_faked) {
        st->st_mode = fr_compose_mode(st->st_mode, local.mode);
    }
}

void fakeroot_patch_stat(struct stat *st, fakeroot_state *fs)
{
    fakeroot_patch_stat_ex(st, fs, NULL, -1);
}

void fakeroot_patch_stat64_ex(struct stat64 *st, fakeroot_state *fs,
                              const fr_record *rec, int fd)
{
    fr_record local;
    bool      have_rec = false;
    uid_t     uid;
    gid_t     gid;

    if (st == NULL || fs == NULL || !fs->enabled) {
        return;
    }

    if (rec != NULL) {
        local    = *rec;
        have_rec = true;
    } else {
        if (fakeroot_lookup(fs, NULL, st->st_dev, st->st_ino, &local) == FR_OK) {
            have_rec = true;
        } else if (fd >= 0 &&
                   fakeroot_lookup_fd(fs, fd, &local) == FR_OK) {
            have_rec = true;
        }
    }

    if (fr_decide_ids(fs, &local, have_rec, fs->real_uid, fs->real_gid,
                      st->st_uid, st->st_gid, &uid, &gid)) {
        st->st_uid = uid;
        st->st_gid = gid;
    }

    if (have_rec && local.mode_faked) {
        st->st_mode = fr_compose_mode(st->st_mode, local.mode);
    }
}

void fakeroot_patch_stat64(struct stat64 *st, fakeroot_state *fs)
{
    fakeroot_patch_stat64_ex(st, fs, NULL, -1);
}

/*
 * statx 的补丁。
 *
 * ⚠ 与 stat 的三点差异，全都必须处理：
 *   1. stx_mask 是「哪些字段有效」的位图，没置位就不能读、更不能改；
 *   2. 要写 stx_mode 必须确保 STATX_MODE 已置位（否则等于凭空造数据）；
 *   3. proot stat.c:171 把 gid 拿去和 getuid() 比了 —— 明显笔误。
 *      本实现按语义修正成 real_gid，见 REPORT.md §6。
 */
void fakeroot_patch_statx_ex(struct statx *stx, fakeroot_state *fs,
                             const fr_record *rec, int fd)
{
    fr_record local;
    bool      have_rec = false;

    if (stx == NULL || fs == NULL || !fs->enabled) {
        return;
    }

    if (rec != NULL) {
        local    = *rec;
        have_rec = true;
    } else {
        /*
         * ⚠ 键必须与写侧同型。
         *
         * 写侧（fr_record_inode_for_path / fr_record_inode_for_fd，以及
         * fakeroot_record_owner_inode 的全部调用点）存的是**完整的
         * `st.st_dev`**，而 statx 只把 dev 拆成 stx_dev_major / stx_dev_minor
         * 两个 __u32。原来这里直接传 stx_dev_major 当 dev_t ——
         * **丢掉了 minor**，于是读侧键与写侧键永不相等（本机实测
         * 0xfe3e vs 0xfe），这次查询就成了死代码。
         *
         * 修法是按内核的编码把两者重新拼回 dev_t。不能写成
         * `stx_dev_major << 32 | minor`：dev_t 的编码是与架构相关的
         * （glibc 的 makedev 在 64 位上把 major 放在高 32 位，但它同时会
         * 向两个位置散列，并由用户态 gnulib 协助解码），手写位移在
         * 不同 libc 上不等价。用 <sys/sysmacros.h> 的 makedev() 才是
         * 与 stat() 那条路径**逐位一致**的还原。
         *
         * 输入类型匹配，无截断：makedev 收 unsigned int，
         * stx_dev_major/minor 是 __u32。
         *
         * 可达性（已实测，见 docs/fakeroot-修复报告.md §F3）：
         *   - rec != NULL        → 不走这里（调用方已按路径预取）；
         *   - rec == NULL, fd>=0 → 本查询 MISS 后由 fakeroot_lookup_fd 兜底，
         *                          功能上被掩盖，但多付一次必然失败的探测；
         *   - rec == NULL, fd<0  → 本查询是**唯一**信息来源。此时修复前
         *                          have_rec 恒为 false，记账里的属主被丢给
         *                          启发式（或直接丢失）→ 同一个文件用 stat
         *                          和 statx 查会得到**不同属主**。
         *                          用「假身份 uid=1000、内核 uid=2000、
         *                          记账 uid=1000」实测：修复前 stx_uid=2000
         *                          （错），修复后 1000（与 stat 一致）。
         */
        dev_t dev = makedev((unsigned int)stx->stx_dev_major,
                            (unsigned int)stx->stx_dev_minor);
        if (fakeroot_lookup(fs, NULL, dev, stx->stx_ino, &local) == FR_OK) {
            have_rec = true;
        } else if (fd >= 0 && fakeroot_lookup_fd(fs, fd, &local) == FR_OK) {
            have_rec = true;
        }
    }

    /* ---- uid ---- */
    if ((stx->stx_mask & STATX_UID) != 0u) {
        uid_t out_uid;
        gid_t out_gid;
        if (fr_decide_ids(fs, &local, have_rec, fs->real_uid, fs->real_gid,
                          stx->stx_uid, stx->stx_gid, &out_uid, &out_gid)) {
            stx->stx_uid = out_uid;
            stx->stx_gid = out_gid;
        }
    } else if (have_rec && local.uid_faked) {
        /* 记账里有显式 chown，而内核这条 statx 没报 uid ⇒ 由我们补上，
         * 并置位 STATX_UID，让调用方知道该字段现在有效。 */
        stx->stx_uid  = local.uid;
        stx->stx_mask |= STATX_UID;
    }

    /* ---- gid ---- */
    if ((stx->stx_mask & STATX_GID) != 0u) {
        uid_t out_uid;
        gid_t out_gid;
        if (fr_decide_ids(fs, &local, have_rec, fs->real_uid, fs->real_gid,
                          stx->stx_uid, stx->stx_gid, &out_uid, &out_gid)) {
            stx->stx_uid = out_uid;
            stx->stx_gid = out_gid;
        }
    } else if (have_rec && local.gid_faked) {
        stx->stx_gid  = local.gid;
        stx->stx_mask |= STATX_GID;
    }

    /* ---- mode ---- */
    if (have_rec && local.mode_faked) {
        mode_t composed = fr_compose_mode((mode_t)stx->stx_mode, local.mode);
        stx->stx_mode  = (uint16_t)(composed & 0xFFFFu);
        stx->stx_mask |= STATX_MODE;
    }
}

void fakeroot_patch_statx(struct statx *stx, fakeroot_state *fs)
{
    fakeroot_patch_statx_ex(stx, fs, NULL, -1);
}

void fakeroot_patch_stat_simple(struct stat *st, uid_t real_uid, uid_t fake_uid,
                                gid_t real_gid, gid_t fake_gid)
{
    if (st == NULL) {
        return;
    }
    if (st->st_uid == real_uid) {
        st->st_uid = fake_uid;
    }
    if (st->st_gid == real_gid) {
        st->st_gid = fake_gid;
    }
}

/* ================================================================== */
/* §5  access(2) / 身份状态机 / 闸门                                    */
/* ================================================================== */

int fakeroot_permission_bits(mode_t file_mode, bool is_owner, bool in_group,
                             bool as_root)
{
    int omode;

    /* helper_functions.c:187-192 */
    if (is_owner || as_root) {
        omode = (int)((file_mode >> 6) & 07u);
    } else if (in_group) {
        omode = (int)((file_mode >> 3) & 07u);
    } else {
        omode = (int)(file_mode & 07u);
    }

    /* helper_functions.c:207-208：root 额外拿到 r+w，但**不拿到 x**。 */
    if (as_root) {
        omode |= 6;
    }

    return omode & 07;
}

fr_access_verdict fakeroot_check_access(const struct stat *st, int mode,
                                        bool st_valid, bool as_root)
{
    int mask = 0;
    int perms;

    /* access.c:35-36：F_OK 只看存在性，模型层面一律放行。
     * 存在性由真实 access() 判定，钩子层负责组合。 */
    if ((mode & F_OK) != 0) {
        return FR_ACCESS_GRANTED;
    }

    /* 没有有效的 stat 结果 ⇒ 没有依据去伪造许可。
     * 判 GRANTED 是为了让真实 access() 的 errno（ENOENT/EACCES）透出去。 */
    if (!st_valid || st == NULL) {
        return FR_ACCESS_GRANTED;
    }

    /* access.c:42-48 */
    if ((mode & R_OK) != 0) {
        mask += 4;
    }
    if ((mode & W_OK) != 0) {
        mask += 2;
    }
    if ((mode & X_OK) != 0) {
        mask += 1;
    }
    if (mask == 0) {
        return FR_ACCESS_GRANTED;
    }

    perms = fakeroot_permission_bits(st->st_mode, false, false, as_root);

    /* access.c:51-53 */
    return ((perms & mask) == mask) ? FR_ACCESS_GRANTED : FR_ACCESS_DENIED;
}

bool fakeroot_access_override(int real_errno, fr_access_verdict model)
{
    /* 真实调用失败只覆盖 EPERM/EACCES 两种（fake_id0.c:549-550 的口径）。
     * ENOENT / EROFS / ELOOP 这些必须原样透出去 —— 否则
     * `test -f missing` 会变成 true，shell 脚本立刻跑飞。 */
    if (real_errno != EPERM && real_errno != EACCES) {
        return false;
    }
    return model == FR_ACCESS_GRANTED;
}

/* ------------------------------------------------------------------ */
/* 状态机                                                             */
/* ------------------------------------------------------------------ */

void fakeroot_state_init(fakeroot_state *fs)
{
    if (fs == NULL) {
        return;
    }
    memset(fs, 0, sizeof(*fs));
    fs->enabled   = false;
    fs->heuristic = FR_HEURISTIC_OWNER;
    fs->caps_active = false;
    fs->keep_caps   = false;
    fs->ngroups     = 0;
}

void fakeroot_state_set_real_ids(fakeroot_state *fs, uid_t ruid, uid_t euid,
                                 gid_t rgid, gid_t egid)
{
    if (fs == NULL) {
        return;
    }
    fs->real_uid  = ruid;
    fs->real_euid = euid;
    fs->real_gid  = rgid;
    fs->real_egid = egid;
}

void fakeroot_state_set_enabled(fakeroot_state *fs, bool enabled)
{
    if (fs == NULL) {
        return;
    }
    fs->enabled = enabled;
    if (enabled) {
        /* 默认的假身份就是 root（uid=gid=0），与参考实现一致。 */
        fs->ruid = fs->euid = fs->suid = fs->fsuid = (uid_t)0;
        fs->rgid = fs->egid = fs->sgid = fs->fsgid = (gid_t)0;
        fs->caps_active = true;
        fs->keep_caps   = false;

        /*
         * ★ 补充组表：默认 **1 个元素 [0]**，不是空表 ★
         *
         * 【实测依据】官方在 fakeroot 下的三侧对照（见
         * docs/身份查询与降权族-原始数据.md）：
         *
         *     getgroups(0, NULL)  官方 = 1      原生 = 6
         *     getgroups(1, buf)   官方 = 1 [0]  原生 = 6
         *
         * 也就是说官方伪造出的身份**自洽**：uid=gid=0 且补充组里也有 0
         * （即"我是 root，主组是 root"）。而 bxroot 之前 `ngroups = 0`，
         * 于是 `id` 的输出是 `gid=0 groups=0`（官方是 `groups=0(root)`）
         * —— 少了一个组，程序做组查询时会看到不一致。
         *
         * 为什么不是"空表"：真实的 root 进程在主组之外通常还有补充组，
         * 但**官方选择只给一个 [0]**，我们与官方对齐而不是与真实内核对齐
         * （这是 fakeroot 的语义 —— 让程序看到"它以为的那个身份"）。
         *
         * 注意组表可以被 `setgroups` 覆盖（见 fakeroot_setgroups），
         * 这里只设初值。
         */
        fs->groups[0]  = (gid_t)0;
        fs->ngroups    = 1;
    }
}

/* fake_id0.c:92-97 的 MAYBE_DROP_CAPS。 */
static void fr_maybe_drop_caps(fakeroot_state *fs, bool prev_root)
{
    if (prev_root && !fs->keep_caps &&
        fs->ruid != (uid_t)0 && fs->euid != (uid_t)0 && fs->suid != (uid_t)0) {
        fs->caps_active = false;
    }
}

static bool fr_any_uid_is_root(const fakeroot_state *fs)
{
    return fs->ruid == (uid_t)0 || fs->euid == (uid_t)0 || fs->suid == (uid_t)0;
}

static bool fr_any_gid_is_root(const fakeroot_state *fs)
{
    return fs->rgid == (gid_t)0 || fs->egid == (gid_t)0 || fs->sgid == (gid_t)0;
}

int fakeroot_setuid(fakeroot_state *fs, uid_t uid)
{
    bool prev_root;
    bool allowed;

    if (fs == NULL) {
        return FR_EINVAL;
    }

    prev_root = fr_any_uid_is_root(fs);

    /* fake_id0.c:112-115 —— 「EPERM: The user is not privileged and uid
     * does not match the real UID or saved set-user-ID」 */
    allowed = (fs->euid == (uid_t)0 || fs->caps_active ||
               uid == fs->ruid || uid == fs->euid || uid == fs->suid);
    if (!allowed) {
        return FR_EPERM;
    }

    /* fake_id0.c:122-125 —— euid 是 root 时，ruid 与 suid 一起被设置。 */
    if (fs->euid == (uid_t)0 || fs->caps_active) {
        fs->ruid = uid;
        fs->suid = uid;
    }
    /* fake_id0.c:130-131 —— 改 euid 时 fsuid 跟随。 */
    fs->euid  = uid;
    fs->fsuid = uid;

    fr_maybe_drop_caps(fs, prev_root);
    return FR_OK;
}

int fakeroot_setgid(fakeroot_state *fs, gid_t gid)
{
    bool prev_root;
    bool allowed;

    if (fs == NULL) {
        return FR_EINVAL;
    }

    prev_root = fr_any_gid_is_root(fs);

    allowed = (fs->egid == (gid_t)0 || fs->caps_active ||
               gid == fs->rgid || gid == fs->egid || gid == fs->sgid);
    if (!allowed) {
        return FR_EPERM;
    }

    if (fs->egid == (gid_t)0 || fs->caps_active) {
        fs->rgid = gid;
        fs->sgid = gid;
    }
    fs->egid  = gid;
    fs->fsgid = gid;

    fr_maybe_drop_caps(fs, prev_root);
    return FR_OK;
}

/* fake_id0.c:147 的 UNCHANGED_ID / UNSET_ID */
static bool fr_uid_unchanged(const fakeroot_state *fs, uid_t u)
{
    return !fr_uid_is_set(u) || u == fs->ruid;
}
static bool fr_gid_unchanged(const fakeroot_state *fs, gid_t g)
{
    return !fr_gid_is_set(g) || g == fs->rgid;
}

int fakeroot_setreuid(fakeroot_state *fs, uid_t r, uid_t e)
{
    bool prev_root;
    bool allowed;

    if (fs == NULL) {
        return FR_EINVAL;
    }

    /* fake_id0.c:155 */
    prev_root = fr_any_uid_is_root(fs);

    /* fake_id0.c:177-181 */
    allowed = (fs->euid == (uid_t)0 || fs->caps_active ||
               (fr_uid_unchanged(fs, e) && fr_uid_unchanged(fs, r)) ||
               (r == fs->euid && (e == fs->ruid || !fr_uid_is_set(e))) ||
               (e == fs->ruid && (r == fs->euid || !fr_uid_is_set(r))) ||
               (e == fs->suid && fr_uid_unchanged(fs, r)));
    if (!allowed) {
        return FR_EPERM;
    }

    /* fake_id0.c:191-197：先处理 euid（suid 的更新依赖旧的 ruid 比较）。 */
    if (fr_uid_is_set(e)) {
        if (e != fs->ruid) {
            fs->suid = e;
        }
        fs->euid  = e;
        fs->fsuid = e;
    }

    /* fake_id0.c:201-205：再处理 ruid。 */
    if (fr_uid_is_set(r)) {
        if (fr_uid_is_set(e)) {
            fs->suid = e;
        }
        fs->ruid = r;
    }

    fr_maybe_drop_caps(fs, prev_root);
    return FR_OK;
}

int fakeroot_setregid(fakeroot_state *fs, gid_t r, gid_t e)
{
    bool prev_root;
    bool allowed;

    if (fs == NULL) {
        return FR_EINVAL;
    }

    prev_root = fr_any_gid_is_root(fs);

    allowed = (fs->egid == (gid_t)0 || fs->caps_active ||
               (fr_gid_unchanged(fs, e) && fr_gid_unchanged(fs, r)) ||
               (r == fs->egid && (e == fs->rgid || !fr_gid_is_set(e))) ||
               (e == fs->rgid && (r == fs->egid || !fr_gid_is_set(r))) ||
               (e == fs->sgid && fr_gid_unchanged(fs, r)));
    if (!allowed) {
        return FR_EPERM;
    }

    if (fr_gid_is_set(e)) {
        if (e != fs->rgid) {
            fs->sgid = e;
        }
        fs->egid  = e;
        fs->fsgid = e;
    }
    if (fr_gid_is_set(r)) {
        if (fr_gid_is_set(e)) {
            fs->sgid = e;
        }
        fs->rgid = r;
    }

    fr_maybe_drop_caps(fs, prev_root);
    return FR_OK;
}

/* fake_id0.c:216-218 的 EQUALS_ANY_ID */
static bool fr_uid_equals_any(const fakeroot_state *fs, uid_t u)
{
    return u == fs->ruid || u == fs->euid || u == fs->suid;
}
static bool fr_gid_equals_any(const fakeroot_state *fs, gid_t g)
{
    return g == fs->rgid || g == fs->egid || g == fs->sgid;
}

int fakeroot_setresuid(fakeroot_state *fs, uid_t r, uid_t e, uid_t s)
{
    bool prev_root;
    bool allowed;

    if (fs == NULL) {
        return FR_EINVAL;
    }

    prev_root = fr_any_uid_is_root(fs);

    /* fake_id0.c:239-242 */
    allowed = (fs->euid == (uid_t)0 || fs->caps_active ||
               ((!fr_uid_is_set(r) || fr_uid_equals_any(fs, r)) &&
                (!fr_uid_is_set(e) || fr_uid_equals_any(fs, e)) &&
                (!fr_uid_is_set(s) || fr_uid_equals_any(fs, s))));
    if (!allowed) {
        return FR_EPERM;
    }

    /* 「If one of the arguments equals -1, the corresponding value is
     *  not changed.」 */
    if (fr_uid_is_set(r)) {
        fs->ruid = r;
    }
    if (fr_uid_is_set(e)) {
        fs->euid  = e;
        fs->fsuid = e;
    }
    if (fr_uid_is_set(s)) {
        fs->suid = s;
    }

    fr_maybe_drop_caps(fs, prev_root);
    return FR_OK;
}

int fakeroot_setresgid(fakeroot_state *fs, gid_t r, gid_t e, gid_t s)
{
    bool prev_root;
    bool allowed;

    if (fs == NULL) {
        return FR_EINVAL;
    }

    prev_root = fr_any_gid_is_root(fs);

    allowed = (fs->egid == (gid_t)0 || fs->caps_active ||
               ((!fr_gid_is_set(r) || fr_gid_equals_any(fs, r)) &&
                (!fr_gid_is_set(e) || fr_gid_equals_any(fs, e)) &&
                (!fr_gid_is_set(s) || fr_gid_equals_any(fs, s))));
    if (!allowed) {
        return FR_EPERM;
    }

    if (fr_gid_is_set(r)) {
        fs->rgid = r;
    }
    if (fr_gid_is_set(e)) {
        fs->egid  = e;
        fs->fsgid = e;
    }
    if (fr_gid_is_set(s)) {
        fs->sgid = s;
    }

    fr_maybe_drop_caps(fs, prev_root);
    return FR_OK;
}

uid_t fakeroot_setfsuid(fakeroot_state *fs, uid_t fsuid)
{
    uid_t old;
    bool  allowed;

    if (fs == NULL) {
        return FR_UNSET_UID;
    }

    old = fs->fsuid;

    /* fake_id0.c:280-282 —— 只有 root/caps，或与 r/e/s/当前 fsuid 之一
     * 相等时才生效；否则**静默失败**（不报错，返回旧值）。 */
    allowed = (fs->euid == (uid_t)0 || fs->caps_active ||
               fsuid == fs->fsuid || fr_uid_equals_any(fs, fsuid));
    if (allowed) {
        fs->fsuid = fsuid;
    }
    return old;
}

gid_t fakeroot_setfsgid(fakeroot_state *fs, gid_t fsgid)
{
    gid_t old;
    bool  allowed;

    if (fs == NULL) {
        return FR_UNSET_GID;
    }

    old = fs->fsgid;

    allowed = (fs->egid == (gid_t)0 || fs->caps_active ||
               fsgid == fs->fsgid || fr_gid_equals_any(fs, fsgid));
    if (allowed) {
        fs->fsgid = fsgid;
    }
    return old;
}

int fakeroot_setgroups(fakeroot_state *fs, const gid_t *list, size_t n)
{
    size_t i;

    if (fs == NULL) {
        return FR_EINVAL;
    }
    /* 内核语义：只有 CAP_SETGID 才能改补充组。 */
    if (!(fs->euid == (uid_t)0 || fs->caps_active)) {
        return FR_EPERM;
    }
    if (n > (size_t)FR_NGROUPS_MAX) {
        return FR_EINVAL;
    }
    if (n > 0 && list == NULL) {
        return FR_EINVAL;
    }

    for (i = 0; i < n; i++) {
        fs->groups[i] = list[i];
    }
    fs->ngroups = (int)n;
    return FR_OK;
}

int fakeroot_getgroups(const fakeroot_state *fs, gid_t *list, size_t size)
{
    int n;

    if (fs == NULL) {
        return FR_EINVAL;
    }
    n = fs->ngroups;
    if (size == 0) {
        return n;          /* 「查询总数」语义 */
    }
    if (list == NULL) {
        return FR_EINVAL;
    }
    if (size < (size_t)n) {
        return FR_EINVAL;  /* 内核返回 EINVAL */
    }
    if (n > 0) {
        memcpy(list, fs->groups, (size_t)n * sizeof(gid_t));
    }
    return n;
}

void fakeroot_set_keepcaps(fakeroot_state *fs, bool on)
{
    if (fs != NULL) {
        fs->keep_caps = on;
    }
}

bool fakeroot_get_keepcaps(const fakeroot_state *fs)
{
    return (fs == NULL) ? false : fs->keep_caps;
}

int fakeroot_gate_chown(const fakeroot_state *fs, const fr_record *cur,
                        uid_t req_uid, gid_t req_gid,
                        uid_t *out_uid, gid_t *out_gid)
{
    uid_t cur_uid = (cur != NULL) ? cur->uid : (uid_t)0;

    if (out_uid != NULL) {
        *out_uid = req_uid;
    }
    if (out_gid != NULL) {
        *out_gid = req_gid;
    }
    if (fs == NULL) {
        return FR_EINVAL;
    }

    /* chown.c:81-83 —— 假 root 想改什么就改什么。 */
    if (fs->euid == (uid_t)0) {
        return FR_OK;
    }

    /* chown.c:86-89 —— 属主只能改组，且 owner 参数被强制回原值。 */
    if (cur != NULL && fs->euid == cur_uid) {
        if (out_uid != NULL) {
            *out_uid = cur_uid;
        }
        if (out_gid != NULL) {
            *out_gid = req_gid;
        }
        return FR_OK;
    }

    /* chown.c:91-92 */
    return FR_EPERM;
}

int fakeroot_gate_chmod(const fakeroot_state *fs, const fr_record *cur)
{
    if (fs == NULL) {
        return FR_EINVAL;
    }
    /* chmod.c:50-51 —— 非属主且非 root ⇒ EPERM。 */
    if (fs->euid == (uid_t)0) {
        return FR_OK;
    }
    if (cur != NULL && fs->euid == cur->uid) {
        return FR_OK;
    }
    return FR_EPERM;
}

fr_chown_action fakeroot_chown_action(int real_ret, int real_errno,
                                      int gate_ret)
{
    /* 真实调用成功 ⇒ 内核真的改了（例如属主自己改自己的组）⇒ 透传。 */
    if (real_ret == 0) {
        return FR_CHOWN_PROPAGATE;
    }

    /* 真实失败的 errno 不是权限问题 ⇒ 是 ENOENT/EROFS/ENOTDIR 之类，
     * 绝不能被吞掉（吞了 dpkg 会以为文件改了属主，实际文件都不存在）。 */
    if (real_errno != EPERM && real_errno != EACCES) {
        return FR_CHOWN_PROPAGATE;
    }

    /* 权限失败，但模型的闸门也说不行 ⇒ 如实报错。 */
    if (gate_ret != FR_OK) {
        return FR_CHOWN_PROPAGATE;
    }

    /* 权限失败纯粹因为真实进程没有 CAP_CHOWN，而假身份有 ⇒ 记账后返回 0。 */
    return FR_CHOWN_FAKE_OK;
}

/* ================================================================== */
/* §6  钩子层：全局状态与真实函数解析                                    */
/* ================================================================== */
#ifndef FAKEROOT_PURE_LOGIC

#include <dlfcn.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

fakeroot_state g_fakeroot;

/* ------------------------------------------------------------------ */
/* 6.1 真实函数指针。全部只在 ensure_real() 里 dlsym(RTLD_NEXT, ...)。  */
/* ------------------------------------------------------------------ */

static int   (*real_stat)(const char *, struct stat *);
static int   (*real_stat64)(const char *, struct stat64 *);
static int   (*real_fstat)(int, struct stat *);
static int   (*real_fstat64)(int, struct stat64 *);
static int   (*real_lstat)(const char *, struct stat *);
static int   (*real_lstat64)(const char *, struct stat64 *);
static int   (*real_fstatat)(int, const char *, struct stat *, int);
static int   (*real_fstatat64)(int, const char *, struct stat64 *, int);
static int   (*real_newfstatat)(int, const char *, struct stat *, int);
static int   (*real_newfstatat64)(int, const char *, struct stat64 *, int);
static int   (*real_statx)(int, const char *, int, unsigned int, struct statx *);
static int   (*real_xstat)(int, const char *, struct stat *);
static int   (*real_lxstat)(int, const char *, struct stat *);
static int   (*real_fxstat)(int, int, struct stat *);
static int   (*real_fxstatat)(int, int, const char *, struct stat *, int);

/* open 家族：**只为「新建文件 ⇒ 记一条属于假身份的属主」而钩**，
 * 不做路径翻译（那是 preload.c 的职责，见 INTEGRATION.md）。 */
static int   (*real_open)(const char *, int, ...);
static int   (*real_open64)(const char *, int, ...);
static int   (*real_openat)(int, const char *, int, ...);
static int   (*real_openat64)(int, const char *, int, ...);
static int   (*real_creat)(const char *, mode_t);

static int   (*real_access)(const char *, int);
static int   (*real_faccessat)(int, const char *, int, int);
static int   (*real_chown)(const char *, uid_t, gid_t);
static int   (*real_fchown)(int, uid_t, gid_t);
static int   (*real_lchown)(const char *, uid_t, gid_t);
static int   (*real_fchownat)(int, const char *, uid_t, gid_t, int);
static int   (*real_chmod)(const char *, mode_t);
static int   (*real_fchmod)(int, mode_t);
static int   (*real_fchmodat)(int, const char *, mode_t, int);
static int   (*real_mknod)(const char *, mode_t, dev_t);
static int   (*real_mknodat)(int, const char *, mode_t, dev_t);

/* setuid 家族的真实版本**永远不该被调用**（提权必须被吞掉），
 * 但为了在「fakeroot 关闭」时透传，还是解析出来。 */
static int   (*real_setuid)(uid_t);
static int   (*real_setgid)(gid_t);
static int   (*real_setreuid)(uid_t, uid_t);
static int   (*real_setregid)(gid_t, gid_t);
static int   (*real_setresuid)(uid_t, uid_t, uid_t);
static int   (*real_setresgid)(gid_t, gid_t, gid_t);
static int   (*real_setgroups)(size_t, const gid_t *);
static int   (*real_getgroups)(int, gid_t *);
static int   (*real_setfsuid)(uid_t);
static int   (*real_setfsgid)(gid_t);

static int   (*real_getresuid)(uid_t *, uid_t *, uid_t *);
static int   (*real_getresgid)(gid_t *, gid_t *, gid_t *);

static bool real_resolved = false;
static bool in_init      = false;

/*
 * 解析全部真实符号。**每个指针在使用前都必须查 NULL**。
 * 这里刻意不做「一次失败就整体放弃」—— glibc 2.39 根本不导出
 * newfstatat / __xstat（见 readelf --dyn-syms 结果），那几项必然是 NULL，
 * 但其余几十项都能用。某一路为 NULL 时对应钩子退化成 errno=ENOSYS。
 */

static void ensure_real(void)
{
    if (real_resolved) {
        return;
    }
    real_resolved = true;

    real_stat        = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "stat");
    real_stat64      = (int (*)(const char *, struct stat64 *))dlsym(RTLD_NEXT, "stat64");
    real_fstat       = (int (*)(int, struct stat *))dlsym(RTLD_NEXT, "fstat");
    real_fstat64     = (int (*)(int, struct stat64 *))dlsym(RTLD_NEXT, "fstat64");
    real_lstat       = (int (*)(const char *, struct stat *))dlsym(RTLD_NEXT, "lstat");
    real_lstat64     = (int (*)(const char *, struct stat64 *))dlsym(RTLD_NEXT, "lstat64");
    real_fstatat     = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "fstatat");
    real_fstatat64   = (int (*)(int, const char *, struct stat64 *, int))dlsym(RTLD_NEXT, "fstatat64");
    real_newfstatat  = (int (*)(int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "newfstatat");
    if (real_newfstatat == NULL) {
        /* glibc 2.33+ 不再导出 newfstatat，现代等价入口就是 fstatat。 */
        real_newfstatat = real_fstatat;
    }
    real_newfstatat64 = (int (*)(int, const char *, struct stat64 *, int))dlsym(RTLD_NEXT, "newfstatat64");
    if (real_newfstatat64 == NULL) {
        real_newfstatat64 = real_fstatat64;
    }
    real_statx       = (int (*)(int, const char *, int, unsigned int, struct statx *))dlsym(RTLD_NEXT, "statx");
    real_xstat       = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__xstat");
    real_lxstat      = (int (*)(int, const char *, struct stat *))dlsym(RTLD_NEXT, "__lxstat");
    real_fxstat      = (int (*)(int, int, struct stat *))dlsym(RTLD_NEXT, "__fxstat");
    real_fxstatat    = (int (*)(int, int, const char *, struct stat *, int))dlsym(RTLD_NEXT, "__fxstatat");

    real_open        = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    real_open64      = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open64");
    real_openat      = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat");
    real_openat64    = (int (*)(int, const char *, int, ...))dlsym(RTLD_NEXT, "openat64");
    real_creat       = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "creat");

    real_access      = (int (*)(const char *, int))dlsym(RTLD_NEXT, "access");
    real_faccessat   = (int (*)(int, const char *, int, int))dlsym(RTLD_NEXT, "faccessat");
    real_chown       = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "chown");
    real_fchown      = (int (*)(int, uid_t, gid_t))dlsym(RTLD_NEXT, "fchown");
    real_lchown      = (int (*)(const char *, uid_t, gid_t))dlsym(RTLD_NEXT, "lchown");
    real_fchownat    = (int (*)(int, const char *, uid_t, gid_t, int))dlsym(RTLD_NEXT, "fchownat");
    real_chmod       = (int (*)(const char *, mode_t))dlsym(RTLD_NEXT, "chmod");
    real_fchmod      = (int (*)(int, mode_t))dlsym(RTLD_NEXT, "fchmod");
    real_fchmodat    = (int (*)(int, const char *, mode_t, int))dlsym(RTLD_NEXT, "fchmodat");
    real_mknod       = (int (*)(const char *, mode_t, dev_t))dlsym(RTLD_NEXT, "mknod");
    real_mknodat     = (int (*)(int, const char *, mode_t, dev_t))dlsym(RTLD_NEXT, "mknodat");

    real_setuid      = (int (*)(uid_t))dlsym(RTLD_NEXT, "setuid");
    real_setgid      = (int (*)(gid_t))dlsym(RTLD_NEXT, "setgid");
    real_setreuid    = (int (*)(uid_t, uid_t))dlsym(RTLD_NEXT, "setreuid");
    real_setregid    = (int (*)(gid_t, gid_t))dlsym(RTLD_NEXT, "setregid");
    real_setresuid   = (int (*)(uid_t, uid_t, uid_t))dlsym(RTLD_NEXT, "setresuid");
    real_setresgid   = (int (*)(gid_t, gid_t, gid_t))dlsym(RTLD_NEXT, "setresgid");
    real_setgroups   = (int (*)(size_t, const gid_t *))dlsym(RTLD_NEXT, "setgroups");
    real_getgroups   = (int (*)(int, gid_t *))dlsym(RTLD_NEXT, "getgroups");
    real_setfsuid    = (int (*)(uid_t))dlsym(RTLD_NEXT, "setfsuid");
    real_setfsgid    = (int (*)(gid_t))dlsym(RTLD_NEXT, "setfsgid");

    real_getresuid   = (int (*)(uid_t *, uid_t *, uid_t *))dlsym(RTLD_NEXT, "getresuid");
    real_getresgid   = (int (*)(gid_t *, gid_t *, gid_t *))dlsym(RTLD_NEXT, "getresgid");
}

/*
 * 用 syscall() 直接读真实身份。
 * 为什么不用 getuid()：那是我们自己的钩子，会返回假身份，
 * 而 fakeroot 的启发式规则恰恰需要「内核真实 uid」。
 * syscall() 不经过 PLT，不会被 LD_PRELOAD 拦截。
 */
static void read_real_identity(void)
{
    uid_t ru = (uid_t)syscall(SYS_getuid);
    uid_t eu = (uid_t)syscall(SYS_geteuid);
    gid_t rg = (gid_t)syscall(SYS_getgid);
    gid_t eg = (gid_t)syscall(SYS_getegid);
    fakeroot_state_set_real_ids(&g_fakeroot, ru, eu, rg, eg);
}

static bool fr_env_truthy(const char *name)
{
    const char *v = getenv(name);
    if (v == NULL || v[0] == '\0') {
        return false;
    }
    /* 与 preload.c:113 的 atoi(env) != 0 保持兼容，同时接受 on/yes/true。 */
    if (v[0] == '0' && v[1] == '\0') {
        return false;
    }
    if (strcmp(v, "false") == 0 || strcmp(v, "no") == 0 ||
        strcmp(v, "off") == 0) {
        return false;
    }
    return true;
}

static size_t fr_env_slots(void);

int fakeroot_hook_init(void)
{
    if (in_init) {
        return FR_OK;   /* 防重入（malloc 钩子可能间接回到这里） */
    }
    in_init = true;

    fakeroot_state_init(&g_fakeroot);
    read_real_identity();

    /* 默认的假 uid/gid 是 0，允许用环境变量覆盖（例如 BXROOT_FAKE_UID=1000）。 */
    {
        const char *eu = getenv("BXROOT_FAKE_UID");
        const char *eg = getenv("BXROOT_FAKE_GID");
        if (eu != NULL && eu[0] != '\0') {
            g_fakeroot.euid = (uid_t)strtoul(eu, NULL, 10);
        }
        if (eg != NULL && eg[0] != '\0') {
            g_fakeroot.egid = (gid_t)strtoul(eg, NULL, 10);
        }
    }

    /* 启发式强度：默认 OWNER。BXROOT_FAKE_ALL=1 切到「全盘归 root」。 */
    if (fr_env_truthy("BXROOT_FAKE_ALL")) {
        g_fakeroot.heuristic = FR_HEURISTIC_ALL;
    } else if (fr_env_truthy("BXROOT_FAKE_OFF")) {
        g_fakeroot.heuristic = FR_HEURISTIC_OFF;
    } else {
        g_fakeroot.heuristic = FR_HEURISTIC_OWNER;
    }

    {
        size_t slots = fr_env_slots();
        g_fakeroot.by_path  = fakeroot_map_create(slots);
        g_fakeroot.by_inode = fakeroot_map_create(slots);
    }
    if (g_fakeroot.by_path == NULL || g_fakeroot.by_inode == NULL) {
        /* 建表失败 ⇒ 退化成「只伪装 get*id」的降级模式，
         * 而不是把整个进程带崩。 */
        g_fakeroot.records_disabled = true;
        fakeroot_map_destroy(g_fakeroot.by_path);
        fakeroot_map_destroy(g_fakeroot.by_inode);
        g_fakeroot.by_path  = NULL;
        g_fakeroot.by_inode = NULL;
    }

    /* 与 preload.c:112-113 同源。 */
    fakeroot_state_set_enabled(&g_fakeroot, fr_env_truthy("BXROOT_FAKEROOT"));

    in_init = false;
    return FR_OK;
}

__attribute__((constructor))
void fakeroot_ctor(void)
{
    (void)fakeroot_hook_init();
}

/* ------------------------------------------------------------------ */
/* 6.2 钩子内的公共动作                                                 */
/* ------------------------------------------------------------------ */

#define FR_ENABLED() (g_fakeroot.enabled)

/*
 * 钩子里统一用它取「当前该报的 uid/gid」。
 * 注意：这些是**不查真实内核**的纯值，real_* 在 init 时读过一次。
 */
static uid_t fr_getuid(void)  { return FR_ENABLED() ? g_fakeroot.ruid  : g_fakeroot.real_uid; }
static uid_t fr_geteuid(void) { return FR_ENABLED() ? g_fakeroot.euid : g_fakeroot.real_euid; }
static gid_t fr_getgid(void)  { return FR_ENABLED() ? g_fakeroot.rgid  : g_fakeroot.real_gid; }
static gid_t fr_getegid(void) { return FR_ENABLED() ? g_fakeroot.egid : g_fakeroot.real_egid; }

/*
 * 记账表的容量（条目数上限）。按「路径键 + inode 键」两条都算进去。
 * 两个环境变量可覆盖，0 / 非法值回到默认。
 */
#define FR_FAKE_SLOTS_DEFAULT 4096u
#define FR_FAKE_SLOTS_MAX     (1u << 16)

static size_t fr_env_slots(void)
{
    const char *v = getenv("BXROOT_FAKE_SLOTS");
    unsigned long n;

    if (v == NULL || v[0] == '\0') {
        return (size_t)FR_FAKE_SLOTS_DEFAULT;
    }
    n = strtoul(v, NULL, 10);
    if (n < 16uL) {
        return 16u;                 /* 太小会把表瞬间打满，给个下限 */
    }
    if (n > (unsigned long)FR_FAKE_SLOTS_MAX) {
        n = (unsigned long)FR_FAKE_SLOTS_MAX;
    }
    return (size_t)n;
}

/*
 * 补上「路径键 + inode 键」这一对。记账时两把键都要写：
 *   - 路径键让紧随其后、**不经过内核 stat** 的查询（例如刚 chown 完
 *     立刻 chown 同一个路径）也能命中；
 *   - inode 键让 rename / 相对路径写法 / 不同别名都能命中。
 * 代价是每条记账占两个槽位。
 */
static void fr_record_inode_for_path(const char *path, uid_t uid, gid_t gid,
                                     bool do_mode, mode_t mode)
{
    struct stat st;

    if (path == NULL || real_stat == NULL) {
        return;
    }
    if (real_stat(path, &st) != 0) {
        return;
    }
    (void)fakeroot_record_owner_inode(&g_fakeroot, st.st_dev, st.st_ino,
                                      uid, gid);
    if (do_mode) {
        (void)fakeroot_record_mode_inode(&g_fakeroot, st.st_dev, st.st_ino,
                                         mode);
    }
}

static void fr_record_inode_for_fd(int fd, uid_t uid, gid_t gid,
                                   bool do_mode, mode_t mode)
{
    struct stat st;

    if (fd < 0 || real_fstat == NULL) {
        return;
    }
    if (real_fstat(fd, &st) != 0) {
        return;
    }
    (void)fakeroot_record_owner_inode(&g_fakeroot, st.st_dev, st.st_ino,
                                      uid, gid);
    if (do_mode) {
        (void)fakeroot_record_mode_inode(&g_fakeroot, st.st_dev, st.st_ino,
                                         mode);
    }
}

/*
 * 打补丁的公共入口：拿内核结果 + 路径，查表、打补丁。
 * path 可以为 NULL（fstat 那一路只有 fd）。
 * fd 传 -1 表示没有 fd。
 */
static void fr_patch_by_path(struct stat *st, const char *path, int fd)
{
    fr_record rec;
    bool have = false;

    if (!FR_ENABLED() || st == NULL) {
        return;
    }

    if (path != NULL) {
        have = (fakeroot_lookup(&g_fakeroot, path, st->st_dev, st->st_ino,
                                &rec) == FR_OK);
    }
    if (!have && fd >= 0) {
        have = (fakeroot_lookup_fd(&g_fakeroot, fd, &rec) == FR_OK);
    }

    fakeroot_patch_stat_ex(st, &g_fakeroot, have ? &rec : NULL, fd);
}

static void fr_patch64_by_path(struct stat64 *st, const char *path, int fd)
{
    fr_record rec;
    bool have = false;

    if (!FR_ENABLED() || st == NULL) {
        return;
    }

    if (path != NULL) {
        have = (fakeroot_lookup(&g_fakeroot, path, st->st_dev, st->st_ino,
                                &rec) == FR_OK);
    }
    if (!have && fd >= 0) {
        have = (fakeroot_lookup_fd(&g_fakeroot, fd, &rec) == FR_OK);
    }

    fakeroot_patch_stat64_ex(st, &g_fakeroot, have ? &rec : NULL, fd);
}

/*
 * chown 家族的公共实现。
 *
 * 顺序**必须**是「先真实调用，失败且是权限问题才记账 + 返回 0」
 * （GAP-ANALYSIS §6.1 第 3 条）。反过来（先记账再调）会在真实调用
 * 成功的情况下留下不一致的记账。
 */
static int fr_do_chown(const char *path, int fd, uid_t uid, gid_t gid,
                       int real_ret, int real_err)
{
    fr_record cur;
    bool  have_cur = false;
    int   gate;
    uid_t out_uid = uid;
    gid_t out_gid = gid;

    if (!FR_ENABLED()) {
        errno = real_err;
        return real_ret;
    }

    /* 取当前记账（没有就用 (0,0) 当缺省，与 proot read_meta_file 的
     * 默认值 {euid, egid} 不同 —— 我们的缺省是「未知」，所以闸门里
     * 只有在 euid != 0 时才依赖它）。 */
    if (path != NULL) {
        have_cur = (fakeroot_lookup(&g_fakeroot, path, (dev_t)0, (ino_t)0,
                                    &cur) == FR_OK);
    }
    if (!have_cur && fd >= 0) {
        have_cur = (fakeroot_lookup_fd(&g_fakeroot, fd, &cur) == FR_OK);
    }
    if (!have_cur) {
        memset(&cur, 0, sizeof(cur));
    }

    gate = fakeroot_gate_chown(&g_fakeroot, &cur, uid, gid, &out_uid, &out_gid);

    if (fakeroot_chown_action(real_ret, real_err, gate) == FR_CHOWN_PROPAGATE) {
        errno = real_err;
        return real_ret;
    }

    /* 记账。同时用路径与 fd 两把键，这样紧随其后的 fstat(fd) 也能命中。 */
    if (path != NULL) {
        (void)fakeroot_record_owner_path(&g_fakeroot, path, out_uid, out_gid);
    }
    if (fd >= 0) {
        (void)fakeroot_record_owner_fd(&g_fakeroot, fd, out_uid, out_gid);
    }

    /* 立刻 stat 一次，把 (dev, ino) 也记上 —— 这样即使调用方随后
     * rename 或换用另一条路径，dev+ino 那一路仍能命中。
     * 这一步失败不影响返回值（记账表允许只有路径键）。 */
    if (path != NULL) {
        fr_record_inode_for_path(path, out_uid, out_gid, false, (mode_t)0);
    } else if (fd >= 0) {
        fr_record_inode_for_fd(fd, out_uid, out_gid, false, (mode_t)0);
    }

    return 0;
}

/* chmod 家族的公共实现。 */
static int fr_do_chmod(const char *path, int fd, mode_t mode,
                       int real_ret, int real_err)
{
    fr_record cur;
    bool have_cur = false;
    int  gate;

    if (!FR_ENABLED()) {
        errno = real_err;
        return real_ret;
    }

    if (path != NULL) {
        have_cur = (fakeroot_lookup(&g_fakeroot, path, (dev_t)0, (ino_t)0,
                                    &cur) == FR_OK);
    }
    if (!have_cur && fd >= 0) {
        have_cur = (fakeroot_lookup_fd(&g_fakeroot, fd, &cur) == FR_OK);
    }
    if (!have_cur) {
        memset(&cur, 0, sizeof(cur));
    }

    gate = fakeroot_gate_chmod(&g_fakeroot, &cur);

    if (fakeroot_chown_action(real_ret, real_err, gate) == FR_CHOWN_PROPAGATE) {
        errno = real_err;
        return real_ret;
    }

    if (path != NULL) {
        (void)fakeroot_record_mode_path(&g_fakeroot, path, mode);
    }
    if (fd >= 0) {
        (void)fakeroot_record_mode_fd(&g_fakeroot, fd, mode);
    }
    if (path != NULL) {
        fr_record_inode_for_path(path, (uid_t)-1, (gid_t)-1, true, mode);
    } else if (fd >= 0) {
        fr_record_inode_for_fd(fd, (uid_t)-1, (gid_t)-1, true, mode);
    }

    return 0;
}

/*
 * access 家族的公共实现。
 * 顺序：先真实调用；失败且是权限问题 ⇒ 用模型再判一次；
 * 模型说放行 ⇒ 吞掉错误返回 0。
 * 还需要一个 stat 来喂模型，但那**只在真实调用失败时**才做，
 * 成功路径上零额外开销。
 */
static int fr_do_access(const char *path, int fd, int mode, int real_ret,
                        int real_err)
{
    struct stat st;
    fr_access_verdict verdict;
    bool st_valid = false;

    if (!FR_ENABLED()) {
        errno = real_err;
        return real_ret;
    }
    if (real_ret == 0) {
        return 0;
    }
    if (real_err != EPERM && real_err != EACCES) {
        errno = real_err;   /* ENOENT / ELOOP … 原样透出 */
        return real_ret;
    }

    if (fd >= 0 && real_fstat != NULL) {
        if (real_fstat(fd, &st) == 0) {
            st_valid = true;
            fr_patch_by_path(&st, NULL, fd);
        }
    } else if (path != NULL && real_stat != NULL) {
        if (real_stat(path, &st) == 0) {
            st_valid = true;
            fr_patch_by_path(&st, path, -1);
        }
    }

    verdict = fakeroot_check_access(st_valid ? &st : NULL, mode, st_valid,
                                    fr_geteuid() == (uid_t)0);

    if (fakeroot_access_override(real_err, verdict)) {
        return 0;
    }

    errno = real_err;
    return real_ret;
}

/* ------------------------------------------------------------------ */
/* 6.3 stat 家族钩子                                                   */
/* ------------------------------------------------------------------ */

/* stat/stat64/lstat/lstat64 的公共骨架。 */
#define FR_STAT_PATH_HOOK(fn, realfn, argtype, patchfn)                       \
    int fn(const char *path, argtype *buf)                                    \
    {                                                                         \
        int ret;                                                              \
        ensure_real();                                                        \
        if (realfn == NULL || buf == NULL) {                                  \
            errno = ENOSYS;                                                   \
            return -1;                                                        \
        }                                                                     \
        ret = realfn(path, buf);                                              \
        if (ret == 0 && FR_ENABLED()) {                                       \
            patchfn(buf, path, -1);                                           \
        }                                                                     \
        return ret;                                                           \
    }

/* 注意：real_stat / real_lstat 在 glibc 里可能是弱符号且为 NULL
 * （glibc 2.39 把 stat/lstat 标成 WEAK），所以 NULL 检查是必需的。 */
FR_STAT_PATH_HOOK(stat,       real_stat,       struct stat,   fr_patch_by_path)
FR_STAT_PATH_HOOK(stat64,     real_stat64,     struct stat64, fr_patch64_by_path)
FR_STAT_PATH_HOOK(lstat,      real_lstat,      struct stat,   fr_patch_by_path)
FR_STAT_PATH_HOOK(lstat64,    real_lstat64,    struct stat64, fr_patch64_by_path)

#define FR_STAT_FD_HOOK(fn, realfn, argtype, patchfn)                         \
    int fn(int fd, argtype *buf)                                              \
    {                                                                         \
        int ret;                                                              \
        ensure_real();                                                        \
        if (realfn == NULL || buf == NULL) {                                  \
            errno = ENOSYS;                                                   \
            return -1;                                                        \
        }                                                                     \
        ret = realfn(fd, buf);                                                \
        if (ret == 0 && FR_ENABLED()) {                                       \
            patchfn(buf, NULL, fd);                                           \
        }                                                                     \
        return ret;                                                           \
    }

FR_STAT_FD_HOOK(fstat,   real_fstat,   struct stat,   fr_patch_by_path)
FR_STAT_FD_HOOK(fstat64, real_fstat64, struct stat64, fr_patch64_by_path)

/* fstatat / newfstatat 家族：路径基是 dirfd，记账键用的是 guest 眼里
 * 的路径（相对路径），所以只有 AT_FDCWD 或绝对路径时才用路径键；
 * 其余情况靠 dev+ino 与 fd 兜底。 */
#define FR_STAT_AT_HOOK(fn, realfn, argtype, patchfn)                         \
    int fn(int dirfd, const char *path, argtype *buf, int flags)              \
    {                                                                         \
        int ret;                                                              \
        const char *key = NULL;                                               \
        ensure_real();                                                        \
        if (realfn == NULL || buf == NULL) {                                  \
            errno = ENOSYS;                                                   \
            return -1;                                                        \
        }                                                                     \
        ret = realfn(dirfd, path, buf, flags);                                \
        if (ret == 0 && FR_ENABLED()) {                                       \
            if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {       \
                key = path;                                                   \
            }                                                                 \
            patchfn(buf, key, -1);                                            \
        }                                                                     \
        return ret;                                                           \
    }

FR_STAT_AT_HOOK(fstatat,      real_fstatat,      struct stat,   fr_patch_by_path)
FR_STAT_AT_HOOK(fstatat64,    real_fstatat64,    struct stat64, fr_patch64_by_path)
FR_STAT_AT_HOOK(newfstatat,   real_newfstatat,   struct stat,   fr_patch_by_path)
FR_STAT_AT_HOOK(newfstatat64, real_newfstatat64, struct stat64, fr_patch64_by_path)

/* statx：唯一一个需要处理 stx_mask 的。 */
int statx(int dirfd, const char *path, int flags, unsigned int mask,
          struct statx *buf)
{
    int ret;
    const char *key = NULL;

    ensure_real();

    /* ⚠ 这里绝不能少 NULL 检查 —— 上游 issue #22 就是 newfstatat 的
     * 空指针解引用造成的稳定 SIGSEGV。 */
    if (real_statx == NULL || buf == NULL) {
        errno = ENOSYS;
        return -1;
    }

    ret = real_statx(dirfd, path, flags, mask, buf);
    if (ret == 0 && FR_ENABLED()) {
        fr_record rec;
        bool have = false;

        if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
            key = path;
        }
        if (key != NULL) {
            have = (fakeroot_lookup(&g_fakeroot, key, (dev_t)0, buf->stx_ino,
                                    &rec) == FR_OK);
        }
        fakeroot_patch_statx_ex(buf, &g_fakeroot, have ? &rec : NULL, -1);
    }
    return ret;
}

/* glibc 2.33 之前的老二进制引用的 __xstat 家族。
 * glibc 2.39 仍导出它们（readelf 可见 GLIBC_2.17 版本），所以不是死代码。 */
int __xstat(int ver, const char *path, struct stat *buf)
{
    int ret;
    ensure_real();
    if (real_xstat == NULL) {
        if (real_stat == NULL || buf == NULL) {
            errno = ENOSYS;
            return -1;
        }
        ret = real_stat(path, buf);
    } else {
        ret = real_xstat(ver, path, buf);
    }
    if (ret == 0 && FR_ENABLED()) {
        fr_patch_by_path(buf, path, -1);
    }
    return ret;
}

int __lxstat(int ver, const char *path, struct stat *buf)
{
    int ret;
    ensure_real();
    if (real_lxstat == NULL) {
        if (real_lstat == NULL || buf == NULL) {
            errno = ENOSYS;
            return -1;
        }
        ret = real_lstat(path, buf);
    } else {
        ret = real_lxstat(ver, path, buf);
    }
    if (ret == 0 && FR_ENABLED()) {
        fr_patch_by_path(buf, path, -1);
    }
    return ret;
}

int __fxstat(int ver, int fd, struct stat *buf)
{
    int ret;
    ensure_real();
    if (real_fxstat == NULL) {
        if (real_fstat == NULL || buf == NULL) {
            errno = ENOSYS;
            return -1;
        }
        ret = real_fstat(fd, buf);
    } else {
        ret = real_fxstat(ver, fd, buf);
    }
    if (ret == 0 && FR_ENABLED()) {
        fr_patch_by_path(buf, NULL, fd);
    }
    return ret;
}

int __fxstatat(int ver, int dirfd, const char *path, struct stat *buf, int flags)
{
    int ret;
    const char *key = NULL;
    ensure_real();
    if (real_fxstatat == NULL) {
        if (real_newfstatat == NULL || buf == NULL) {
            errno = ENOSYS;
            return -1;
        }
        ret = real_newfstatat(dirfd, path, buf, flags);
    } else {
        ret = real_fxstatat(ver, dirfd, path, buf, flags);
    }
    if (ret == 0 && FR_ENABLED()) {
        if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
            key = path;
        }
        fr_patch_by_path(buf, key, -1);
    }
    return ret;
}

/* ------------------------------------------------------------------ */
/* 6.4 身份查询钩子                                                    */
/* ------------------------------------------------------------------ */

uid_t getuid(void)  { ensure_real(); return fr_getuid();  }
uid_t geteuid(void) { ensure_real(); return fr_geteuid(); }
gid_t getgid(void)  { ensure_real(); return fr_getgid();  }
gid_t getegid(void) { ensure_real(); return fr_getegid(); }

int getresuid(uid_t *r, uid_t *e, uid_t *s)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_getresuid == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return real_getresuid(r, e, s);
    }
    /* 三个出参任一为 NULL 都要能容忍（内核允许 NULL）。 */
    if (r != NULL) { *r = g_fakeroot.ruid; }
    if (e != NULL) { *e = g_fakeroot.euid; }
    if (s != NULL) { *s = g_fakeroot.suid; }
    return 0;
}

int getresgid(gid_t *r, gid_t *e, gid_t *s)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_getresgid == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return real_getresgid(r, e, s);
    }
    if (r != NULL) { *r = g_fakeroot.rgid; }
    if (e != NULL) { *e = g_fakeroot.egid; }
    if (s != NULL) { *s = g_fakeroot.sgid; }
    return 0;
}

/*
 * getgroups 的两段式调用约定：
 *   getgroups(0, NULL)          ⇒ 返回组数
 *   getgroups(size, list)       ⇒ 返回实际写入数
 * fake_id0.c:1011-1015 是直接把 syscall 置空、结果写 0 —— 那样
 * `id -G` 会输出空集，且 `getgroups(0,NULL)` 返回 0 会让调用方
 * 以为「没有补充组」。这里真的把记账的组回放出去。
 */
int getgroups(int size, gid_t *list)
{
    int n;

    ensure_real();
    if (!FR_ENABLED()) {
        if (real_getgroups == NULL) {
            errno = ENOSYS;
            return -1;
        }
        return real_getgroups(size, list);
    }

    n = fakeroot_getgroups(&g_fakeroot, list, (size_t)(size < 0 ? 0 : size));
    if (n < 0) {
        errno = EINVAL;
        return -1;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* 6.5 身份变更钩子（提权一律吞掉，绝不下发内核）                        */
/* ------------------------------------------------------------------ */

int setuid(uid_t uid)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setuid == NULL) { errno = ENOSYS; return -1; }
        return real_setuid(uid);
    }
    if (fakeroot_setuid(&g_fakeroot, uid) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int setgid(gid_t gid)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setgid == NULL) { errno = ENOSYS; return -1; }
        return real_setgid(gid);
    }
    if (fakeroot_setgid(&g_fakeroot, gid) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int setreuid(uid_t r, uid_t e)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setreuid == NULL) { errno = ENOSYS; return -1; }
        return real_setreuid(r, e);
    }
    if (fakeroot_setreuid(&g_fakeroot, r, e) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int setregid(gid_t r, gid_t e)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setregid == NULL) { errno = ENOSYS; return -1; }
        return real_setregid(r, e);
    }
    if (fakeroot_setregid(&g_fakeroot, r, e) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int setresuid(uid_t r, uid_t e, uid_t s)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setresuid == NULL) { errno = ENOSYS; return -1; }
        return real_setresuid(r, e, s);
    }
    if (fakeroot_setresuid(&g_fakeroot, r, e, s) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

int setresgid(gid_t r, gid_t e, gid_t s)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setresgid == NULL) { errno = ENOSYS; return -1; }
        return real_setresgid(r, e, s);
    }
    if (fakeroot_setresgid(&g_fakeroot, r, e, s) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

/*
 * setfsuid/setfsgid 的返回值是**旧值**，且**永远返回成功**
 * （man setfsuid：「On success, the previous value of fsuid is returned.
 *  On error, the current value of fsuid is returned.」——
 *  也就是说调用方无法从返回值区分成功与失败）。
 */
int setfsuid(uid_t fsuid)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setfsuid == NULL) { errno = ENOSYS; return -1; }
        return real_setfsuid(fsuid);
    }
    return (int)fakeroot_setfsuid(&g_fakeroot, fsuid);
}

int setfsgid(gid_t fsgid)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setfsgid == NULL) { errno = ENOSYS; return -1; }
        return real_setfsgid(fsgid);
    }
    return (int)fakeroot_setfsgid(&g_fakeroot, fsgid);
}

int setgroups(size_t size, const gid_t *list)
{
    ensure_real();
    if (!FR_ENABLED()) {
        if (real_setgroups == NULL) { errno = ENOSYS; return -1; }
        return real_setgroups(size, list);
    }
    if (fakeroot_setgroups(&g_fakeroot, list, size) != FR_OK) {
        errno = EPERM;
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 6.6 chown / chmod / mknod 钩子                                      */
/* ------------------------------------------------------------------ */

int chown(const char *path, uid_t uid, gid_t gid)
{
    int ret, err;
    ensure_real();
    if (real_chown == NULL) { errno = ENOSYS; return -1; }
    ret = real_chown(path, uid, gid);
    err = errno;
    if (ret == 0) {
        /* 真实成功 —— 但记账仍要更新，否则后续 stat 会看到内核的新属主，
         * 而记账表里还是旧的，两边打架。 */
        if (FR_ENABLED() && path != NULL) {
            (void)fakeroot_record_owner_path(&g_fakeroot, path, uid, gid);
        }
        return 0;
    }
    return fr_do_chown(path, -1, uid, gid, ret, err);
}

int fchown(int fd, uid_t uid, gid_t gid)
{
    int ret, err;
    ensure_real();
    if (real_fchown == NULL) { errno = ENOSYS; return -1; }
    ret = real_fchown(fd, uid, gid);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED()) {
            (void)fakeroot_record_owner_fd(&g_fakeroot, fd, uid, gid);
        }
        return 0;
    }
    return fr_do_chown(NULL, fd, uid, gid, ret, err);
}

int lchown(const char *path, uid_t uid, gid_t gid)
{
    int ret, err;
    ensure_real();
    if (real_lchown == NULL) { errno = ENOSYS; return -1; }
    ret = real_lchown(path, uid, gid);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED() && path != NULL) {
            (void)fakeroot_record_owner_path(&g_fakeroot, path, uid, gid);
        }
        return 0;
    }
    return fr_do_chown(path, -1, uid, gid, ret, err);
}

/*
 * fchownat 的参数口径随 flags 变化，这正是官方那个
 * fake_id0_patch_fchownat_args 存在的原因：
 *   AT_SYMLINK_NOFOLLOW ⇒ 作用于符号链接本身（等价 lchown）
 *   AT_EMPTY_PATH        ⇒ path 为空串，作用于 dirfd 自身
 * 我们两种都处理：前者用路径键（不动 dev+ino 的 post-stat），
 * 后者退化成 fd 键。
 */
int fchownat(int dirfd, const char *path, uid_t uid, gid_t gid, int flags)
{
    int ret, err;
    const char *key = NULL;
    int fd = -1;

    ensure_real();
    if (real_fchownat == NULL) { errno = ENOSYS; return -1; }

    if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
        key = path;
    }
    if ((flags & AT_EMPTY_PATH) != 0 && (path == NULL || path[0] == '\0')) {
        fd = dirfd;
    }

    ret = real_fchownat(dirfd, path, uid, gid, flags);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED()) {
            if (key != NULL) {
                (void)fakeroot_record_owner_path(&g_fakeroot, key, uid, gid);
            }
            if (fd >= 0) {
                (void)fakeroot_record_owner_fd(&g_fakeroot, fd, uid, gid);
            }
        }
        return 0;
    }
    return fr_do_chown(key, fd, uid, gid, ret, err);
}

int chmod(const char *path, mode_t mode)
{
    int ret, err;
    ensure_real();
    if (real_chmod == NULL) { errno = ENOSYS; return -1; }
    ret = real_chmod(path, mode);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED() && path != NULL) {
            (void)fakeroot_record_mode_path(&g_fakeroot, path, mode);
        }
        return 0;
    }
    return fr_do_chmod(path, -1, mode, ret, err);
}

int fchmod(int fd, mode_t mode)
{
    int ret, err;
    ensure_real();
    if (real_fchmod == NULL) { errno = ENOSYS; return -1; }
    ret = real_fchmod(fd, mode);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED()) {
            (void)fakeroot_record_mode_fd(&g_fakeroot, fd, mode);
        }
        return 0;
    }
    return fr_do_chmod(NULL, fd, mode, ret, err);
}

int fchmodat(int dirfd, const char *path, mode_t mode, int flags)
{
    int ret, err;
    const char *key = NULL;

    ensure_real();
    if (real_fchmodat == NULL) { errno = ENOSYS; return -1; }

    if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
        key = path;
    }

    ret = real_fchmodat(dirfd, path, mode, flags);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED() && key != NULL) {
            (void)fakeroot_record_mode_path(&g_fakeroot, key, mode);
        }
        return 0;
    }
    return fr_do_chmod(key, -1, mode, ret, err);
}

/*
 * mknod/mknodat。
 *
 * 为什么这里**不**伪造成功：mknod 创建的是设备节点/管道，
 * 内核会真实创建文件（用户有目录写权限时 mknod 普通文件是允许的），
 * 只有 S_IFCHR/S_IFBLK 需要 CAP_MKNOD。
 * 我们的处理是：真实调用；失败且是 EPERM/EACCES 且假身份是 root ⇒
 * 返回 0 并记账属主（节点没真的建出来，但 dpkg 的 postinst 只关心
 * 「mknod 成功了吗」；真要设备节点的话 bxroot 需要另一套 bind 方案，
 * 那超出本模块范围，已记入 REPORT.md §7）。
 */
int mknod(const char *path, mode_t mode, dev_t dev)
{
    int ret, err;
    ensure_real();
    if (real_mknod == NULL) { errno = ENOSYS; return -1; }
    ret = real_mknod(path, mode, dev);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED() && path != NULL) {
            (void)fakeroot_record_mode_path(&g_fakeroot, path, mode);
            (void)fakeroot_record_owner_path(&g_fakeroot, path,
                                             g_fakeroot.euid, g_fakeroot.egid);
        }
        return 0;
    }
    if (!FR_ENABLED() || (err != EPERM && err != EACCES) ||
        g_fakeroot.euid != (uid_t)0) {
        errno = err;
        return ret;
    }
    if (path != NULL) {
        (void)fakeroot_record_mode_path(&g_fakeroot, path, mode);
        (void)fakeroot_record_owner_path(&g_fakeroot, path,
                                         g_fakeroot.euid, g_fakeroot.egid);
    }
    return 0;
}

int mknodat(int dirfd, const char *path, mode_t mode, dev_t dev)
{
    int ret, err;
    const char *key = NULL;

    ensure_real();
    if (real_mknodat == NULL) { errno = ENOSYS; return -1; }

    if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
        key = path;
    }

    ret = real_mknodat(dirfd, path, mode, dev);
    err = errno;
    if (ret == 0) {
        if (FR_ENABLED() && key != NULL) {
            (void)fakeroot_record_mode_path(&g_fakeroot, key, mode);
            (void)fakeroot_record_owner_path(&g_fakeroot, key,
                                             g_fakeroot.euid, g_fakeroot.egid);
        }
        return 0;
    }
    if (!FR_ENABLED() || (err != EPERM && err != EACCES) ||
        g_fakeroot.euid != (uid_t)0) {
        errno = err;
        return ret;
    }
    if (key != NULL) {
        (void)fakeroot_record_mode_path(&g_fakeroot, key, mode);
        (void)fakeroot_record_owner_path(&g_fakeroot, key,
                                         g_fakeroot.euid, g_fakeroot.egid);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 6.7 open / creat 钩子（只为「新建文件记账」）                         */
/* ------------------------------------------------------------------ */

/*
 * ⚠⚠ 集成注意（INTEGRATION.md §3 有详细说明）⚠⚠
 *
 * preload.c 已经钩了 open/open64/openat/openat64 做**路径翻译**。
 * 本模块的 open 钩子**不做**任何路径翻译，只做「新建文件记账」。
 * 两者绝不能同时生效 —— 那会形成两条 open 符号，链接顺序决定谁赢，
 * 而输的那条会静默丢掉自己的功能。
 *
 * 所以有两种集成方式，二选一：
 *   (A) 推荐：**不要**把本文件的 open 钩子编进去。改为在 preload.c 的
 *       现有 open 钩子里，真实调用返回成功后插一行
 *       `fakeroot_hook_record_create(translated_or_original, flags, mode);`
 *       （函数由本模块导出，见下方 fakeroot_hook_record_create）。
 *   (B) 把路径翻译也搬进本模块 —— 不推荐，等于把两个子系统耦死。
 *
 * 为了让 (A) 可行，本模块把 open 钩子的**全部逻辑**抽成一个可复用函数
 * fakeroot_hook_record_create()，open/openat/creat 钩子只是它的薄封装。
 * 定义 FAKEROOT_NO_OPEN_HOOKS 可以把这三个钩子整段关掉。
 */
#ifndef FAKEROOT_NO_OPEN_HOOKS

/*
 * 真实 open 成功后调用它。flags 里的 O_CREAT/O_EXCL 与 mode 用来判断
 * 「是不是新建」。返回 0 表示不需要记账。
 */
int fakeroot_hook_record_create(const char *path, int flags, mode_t mode)
{
    struct stat st;

    if (path == NULL || !FR_ENABLED()) {
        return -1;
    }
    /* 只有可能创建文件的 open 才需要记账。O_TMPFILE 的 path 是目录，
     * 且创建出来的文件没有名字 ⇒ 无法用路径键，跳过（inode 键会在
     * 后续第一次 stat 时被别的路径补上）。 */
    if ((flags & (O_CREAT | O_TMPFILE)) == 0) {
        return -1;
    }
    if ((flags & O_TMPFILE) == O_TMPFILE) {
        return -1;
    }

    (void)fakeroot_record_create_path(&g_fakeroot, path, mode,
                                      g_fakeroot.euid, g_fakeroot.egid);

    /* 再补一条 inode 键：新建的文件随后几乎必然被 stat 一次
     * （dpkg/tar 都是这个模式），有了 inode 键即使路径写法变了也能命中。 */
    if (real_stat != NULL && real_stat(path, &st) == 0) {
        (void)fakeroot_record_owner_inode(&g_fakeroot, st.st_dev, st.st_ino,
                                          g_fakeroot.euid, g_fakeroot.egid);
        (void)fakeroot_record_mode_inode(&g_fakeroot, st.st_dev, st.st_ino,
                                         mode);
    }
    return 0;
}

/* 钩子内部用：处理可变的第三个参数。 */
static mode_t fr_va_mode(int flags, va_list ap)
{
    if ((flags & (O_CREAT | O_TMPFILE)) != 0) {
        return (mode_t)va_arg(ap, mode_t);
    }
    return (mode_t)0;
}

int open(const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;
    int     ret;

    ensure_real();
    if (real_open == NULL) { errno = ENOSYS; return -1; }

    va_start(ap, flags);
    mode = fr_va_mode(flags, ap);
    va_end(ap);

    ret = real_open(path, flags, mode);
    if (ret >= 0) {
        (void)fakeroot_hook_record_create(path, flags, mode);
    }
    return ret;
}

int open64(const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;
    int     ret;

    ensure_real();
    if (real_open64 == NULL) { errno = ENOSYS; return -1; }

    va_start(ap, flags);
    mode = fr_va_mode(flags, ap);
    va_end(ap);

    ret = real_open64(path, flags, mode);
    if (ret >= 0) {
        (void)fakeroot_hook_record_create(path, flags, mode);
    }
    return ret;
}

int openat(int dirfd, const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;
    int     ret;
    const char *key = NULL;

    ensure_real();
    if (real_openat == NULL) { errno = ENOSYS; return -1; }

    va_start(ap, flags);
    mode = fr_va_mode(flags, ap);
    va_end(ap);

    ret = real_openat(dirfd, path, flags, mode);
    if (ret >= 0) {
        if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
            key = path;
        }
        if (key != NULL) {
            (void)fakeroot_hook_record_create(key, flags, mode);
        }
    }
    return ret;
}

int openat64(int dirfd, const char *path, int flags, ...)
{
    va_list ap;
    mode_t  mode;
    int     ret;
    const char *key = NULL;

    ensure_real();
    if (real_openat64 == NULL) { errno = ENOSYS; return -1; }

    va_start(ap, flags);
    mode = fr_va_mode(flags, ap);
    va_end(ap);

    ret = real_openat64(dirfd, path, flags, mode);
    if (ret >= 0) {
        if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
            key = path;
        }
        if (key != NULL) {
            (void)fakeroot_hook_record_create(key, flags, mode);
        }
    }
    return ret;
}

int creat(const char *path, mode_t mode)
{
    int ret;

    ensure_real();
    if (real_creat == NULL) { errno = ENOSYS; return -1; }

    ret = real_creat(path, mode);
    if (ret >= 0) {
        (void)fakeroot_hook_record_create(path, O_CREAT | O_WRONLY | O_TRUNC,
                                          mode);
    }
    return ret;
}

#endif /* !FAKEROOT_NO_OPEN_HOOKS */

/* ------------------------------------------------------------------ */
/* 6.8 access 钩子                                                     */
/* ------------------------------------------------------------------ */

int access(const char *path, int mode)
{
    int ret, err;
    ensure_real();
    if (real_access == NULL) { errno = ENOSYS; return -1; }
    ret = real_access(path, mode);
    err = errno;
    if (ret == 0 || !FR_ENABLED()) {
        return ret;
    }
    return fr_do_access(path, -1, mode, ret, err);
}

int faccessat(int dirfd, const char *path, int mode, int flags)
{
    int ret, err;
    const char *key = NULL;

    ensure_real();
    if (real_faccessat == NULL) { errno = ENOSYS; return -1; }

    if (path != NULL && (path[0] == '/' || dirfd == AT_FDCWD)) {
        key = path;
    }

    ret = real_faccessat(dirfd, path, mode, flags);
    err = errno;
    if (ret == 0 || !FR_ENABLED()) {
        return ret;
    }
    /* AT_EMPTY_PATH 时按 fd 判。 */
    if ((flags & AT_EMPTY_PATH) != 0 && (path == NULL || path[0] == '\0')) {
        return fr_do_access(NULL, dirfd, mode, ret, err);
    }
    return fr_do_access(key, -1, mode, ret, err);
}

#endif /* !FAKEROOT_PURE_LOGIC */

/* ================================================================== */
/* §7  钩子清单（供 INTEGRATION.md / 审查者核对）                        */
/* ================================================================== */
/*
 * stat 家族（14）：stat stat64 fstat fstat64 lstat lstat64
 *                  fstatat fstatat64 newfstatat newfstatat64 statx
 *                  __xstat __lxstat __fxstat __fxstatat
 * 身份查询（7）：  getuid geteuid getgid getegid
 *                  getresuid getresgid getgroups
 * 身份变更（11）： setuid setgid setreuid setregid setresuid setresgid
 *                  setgroups setfsuid setfsgid
 *                  （prctl(PR_SET_KEEPCAPS) 的镜像在 §6.5 的
 *                    fakeroot_set_keepcaps 里，钩子层不拦 prctl，
 *                    因为拦它要重写整个可变参数签名，收益不抵风险。）
 * 属主/权限（9）：  chown fchown lchown fchownat
 *                  chmod fchmod fchmodat
 *                  mknod mknodat
 * access（2）：     access faccessat
 * 新建记账（5）：   open open64 openat openat64 creat
 *                  （可用 -DFAKEROOT_NO_OPEN_HOOKS 关掉，见 §6.7）
 * ------------------------------------------------------------------
 * 合计 48 个对外符号（关掉 open 家族则 43 个）。
 */
