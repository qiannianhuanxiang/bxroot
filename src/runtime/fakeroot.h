/*
 * fakeroot.h -- bxroot 的 fakeroot（uid/gid 伪装）层。
 *
 * 背景（上游 proroot issue #12「sudo 安装失败」）
 * ------------------------------------------------
 * 克隆版只钩了 getuid/getgid/geteuid/getegid/getpid 五个函数。这不够：
 *   - `dpkg` / `apt` 解包后要读文件属主，读到的是内核真实 uid（2000 或 0）
 *     而不是伪装的 0 → "warning: ignoring ... ownership"，严重时 configure 失败；
 *   - `pnpm` / `npm` 的属主检查失败；
 *   - `tar` 把错误属主写进归档；
 *   - `chown` 看起来毫无效果（后面的 stat 仍显示旧属主），并且真实 chown
 *     对非 root 进程直接 EPERM。
 * 完整语义必须包含 **stat 结果补丁** + **chown 记账**，而不只是 get*id 的返回值。
 * 这一点已由 GAP-ANALYSIS.md §2.1 的活体实测证实（官方 proroot 里
 * `stat -c %u` 对内核属主 10655 的文件返回 0，`chown 12345:12345` 返回 0）。
 *
 * 本文件的分层
 * ------------
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │ 第 1 层：纯逻辑（无 syscall、可单元测试、无隐藏全局态）       │
 *   │   fakeroot_state      伪装身份状态机（r/e/s/fs uid+gid、umask、caps）│
 *   │   fakeroot_map        属主/权限记账表（有界哈希 + 近似 LRU）  │
 *   │   fakeroot_patch_*    对 stat / stat64 / statx 结果打补丁     │
 *   │   fakeroot_check_access  access(2) 的仿真判定                 │
 *   │   fakeroot_setuid 家族  setuid/setgid/setresuid/... 的状态机  │
 *   └──────────────────────────────────────────────────────────────┘
 *   ┌──────────────────────────────────────────────────────────────┐
 *   │ 第 2 层：钩子层（LD_PRELOAD，需要 libdl 与 libc）             │
 *   │   __attribute__((constructor)) fakeroot_ctor()               │
 *   │   以及 45 个 LD_PRELOAD 钩子，见文件末尾的清单               │
 *   └──────────────────────────────────────────────────────────────┘
 * 只想要纯逻辑的测试程序请定义 FAKEROOT_PURE_LOGIC 后再 include 本头文件。
 *
 * 上游参考（行号已逐一核对，见 REPORT.md §2）
 * -------------------------------------------
 *   proot/src/extension/fake_id0/fake_id0.c:102-137   SETXID
 *   proot/src/extension/fake_id0/fake_id0.c:152-211   SETREXID
 *   proot/src/extension/fake_id0/fake_id0.c:223-266   SETRESXID
 *   proot/src/extension/fake_id0/fake_id0.c:271-291   SETFSXID
 *   proot/src/extension/fake_id0/fake_id0.c:92-97     MAYBE_DROP_CAPS
 *   proot/src/extension/fake_id0/fake_id0.c:535-559   handle_perm_err_exit_end
 *   proot/src/extension/fake_id0/fake_id0.c:1011-1015 getgroups/setgroups
 *   proot/src/extension/fake_id0/stat.c:32-48          stat 补丁（ptrace 分支）
 *   proot/src/extension/fake_id0/stat.c:115-131        meta sidecar 合成公式
 *   proot/src/extension/fake_id0/stat.c:160-177        handle_statx
 *   proot/src/extension/fake_id0/chown.c:71-96         chown 权限闸门
 *   proot/src/extension/fake_id0/chmod.c:49-55         chmod 权限闸门
 *   proot/src/extension/fake_id0/access.c:33-54        access 判定
 *   proot/src/extension/fake_id0/helper_functions.c:167-210  get_permissions()
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef FAKEROOT_H
#define FAKEROOT_H

/*
 * 必须在任何系统头文件之前定义：struct stat64 需要 _LARGEFILE64_SOURCE，
 * S_IFMT / S_ISLNK 等需要 __USE_MISC（由 _GNU_SOURCE 带出）。
 * 定义晚了这些符号就不可见，编译期报"未声明"，而它们正是本模块的核心。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================== */
/* 0. 常量与错误码                                                     */
/* ================================================================== */

/* 记账表类型的前置声明：fakeroot_state 里有指针字段要用到它。
 * 完整定义在第 2 节。 */
typedef struct fakeroot_map fakeroot_map;

/* 记账表里的路径上限，含结尾 NUL。与 Linux 的 PATH_MAX 一致。 */
#define FR_PATH_MAX 4096

/* 默认表容量：必须是 2 的幂（开放寻址 + 位掩码取模）。 */
#define FR_MAP_DEFAULT_SLOTS 1024u

/* 表容量的硬上限，防止误配置导致内存爆掉。 */
#define FR_MAP_MAX_SLOTS (1u << 20)

/* 记账表的装载率阈值（百分比）。开放寻址在线性探测 + 删除标记下，
 * 超过这个比例探测链会明显变长，所以到此就先淘汰/压实。 */
#define FR_MAP_LOAD_PERCENT 75u

/* 一次淘汰扫描最多驱逐多少个条目（避免插入退化成 O(n)）。 */
#define FR_MAP_EVICT_BATCH 8u

/* 保存的补充组上限。内核 NGROUPS_MAX 是 65536，但我们只需要一个能
 * 覆盖容器实际用量的值；超过就按内核语义返回 EINVAL。
 * （proot 干脆整个吃掉 getgroups/setgroups，见 fake_id0.c:1011-1015；
 *  这里做得更细，真的记账并回放。） */
#define FR_NGROUPS_MAX 64

/* 纯逻辑函数的返回码。注意：钩子层对外返回的是 errno 的负值或落 errno。 */
enum {
    FR_OK           =  0,
    FR_ENOENT       = -1,   /* 表里没有该条目                        */
    FR_ENOMEM       = -2,   /* malloc 失败或容量非法                 */
    FR_EFULL        = -3,   /* 表已满且无淘汰能力                    */
    FR_ENAMETOOLONG = -4,   /* 路径超过 FR_PATH_MAX                  */
    FR_EINVAL       = -5,   /* 参数非法                              */
    FR_EPERM        = -6,   /* 权限不足（chown/chmod 闸门）          */
    FR_EACCES       = -7    /* access(2) 判定失败                    */
};

/* access(2) 的判定结论。 */
typedef enum {
    FR_ACCESS_GRANTED = 0,   /* 放行                                    */
    FR_ACCESS_DENIED  = 1    /* 拒绝（钩子层落 errno = EACCES 返回 -1） */
} fr_access_verdict;

/* chown 家族钩子的最终动作。 */
typedef enum {
    FR_CHOWN_PROPAGATE = 0,  /* 透传真实调用的返回值与 errno            */
    FR_CHOWN_FAKE_OK   = 1   /* 吞掉 EPERM/EACCES，记账后返回 0         */
} fr_chown_action;

/* ================================================================== */
/* 1. 伪装身份状态                                                     */
/* ================================================================== */

/*
 * stat 补丁的启发式强度（记账表未命中时用什么规则改 st_uid/st_gid）。
 *
 * 三个档位都有出处，因此都实现，由集成方选：
 *
 *   FR_HEURISTIC_OFF   —— 只信记账表，stat 结果原样返回。零误伤，但
 *                         issue #12 修不好：dpkg 解包出来的文件（内核属主
 *                         是 Android 应用 uid）仍会读成 10655。
 *                         适用：只想让 chown 记账生效、不想动其他任何东西。
 *
 *   FR_HEURISTIC_OWNER —— st_uid == real_uid ⇒ euid，st_gid == real_gid ⇒ egid。
 *                        默认值。与 proot fake_id0 的 ptrace 分支字面一致
 *                         （stat.c:43-48「Override only if the file is owned by
 *                          the current user」），也覆盖官方 proroot 的实测
 *                          行为（GAP-ANALYSIS §2.1：内核属主 10655 的文件
 *                          在容器里 `stat -c %u` 读出 0）。
 *                         信息不丢失：真正属于 system/其他 uid 的文件保持原样。
 *
 *   FR_HEURISTIC_ALL   —— 不看内核值，st_uid/st_gid 一律改成 euid/egid。
 *                        即 GAP-ANALYSIS §6.1 第 1 条描述的「全盘归 root」。
 *                         是 OWNER 的超集（fake uid == 0 时把 10655 与 1000
 *                         都映射成 0），代价是丢掉「这个文件其实属于
 *                         system uid」这一信息。想逐字复现官方二进制行为的
 *                         话选它。
 */
typedef enum {
    FR_HEURISTIC_OFF   = 0,
    FR_HEURISTIC_OWNER = 1,
    FR_HEURISTIC_ALL   = 2
} fr_heuristic_mode;

/*
 * fakeroot_state -- 一个进程的「假身份」。
 *
 * 字段与 proot 的 Config（fake_id0/config.h）逐字段对应，语义来自
 * fake_id0.c:102-291 的四个宏。之所以要 r/e/s/fs 四套 id，是因为
 * setuid 家族在真实内核里就是维护这四个值，伪造也必须让
 * `setresuid(-1, 1000, -1)` 之后的 getuid()/geteuid()/getresuid()
 * 全部自洽 —— 否则 sudo、login、dpkg 的 postinst 会立刻发现矛盾。
 */
typedef struct {
    /* --- 总开关；false 时所有 patch/查询立即返回，行为等同未启用 --- */
    bool enabled;

    /* --- 假身份 --- */
    uid_t ruid, euid, suid, fsuid;
    gid_t rgid, egid, sgid, fsgid;

    /* 补充组集合（getgroups/setgroups）。 */
    gid_t groups[FR_NGROUPS_MAX];
    int   ngroups;

    /*
     * 记账未命中时 stat 补丁的启发式强度。默认 FR_HEURISTIC_OWNER。
     * 详见文件上方 fr_heuristic_mode 的说明。
     */
    fr_heuristic_mode heuristic;

    /* --- 真实身份（由调用方在初始化时读一次，纯逻辑层不自己读） --- */
    uid_t real_uid, real_euid;
    gid_t real_gid, real_egid;

    /* --- proot Config 的 caps_active / keep_caps --- */
    /* 是否在伪装下持有 CAP_SETUID/CAP_SETGID。fake_id0.c:92-97 的
     * MAYBE_DROP_CAPS：当 r/e/s uid 从「至少一个 0」变成「全非 0」时清除，
     * 除非 prctl(PR_SET_KEEPCAPS) 置过位。 */
    bool caps_active;
    bool keep_caps;

    /* --- 记账表 --- */
    /* 按路径键（chown("a/b") 与 chown("/abs/a/b") 归一到同一键）。 */
    fakeroot_map *by_path;
    /* 按 dev+ino 键（fchown(fd) / 文件被 rename 后仍能命中）。 */
    fakeroot_map *by_inode;
    /* 两个表都关掉时为 true：patch_stat 退化为纯启发式规则。 */
    bool records_disabled;
} fakeroot_state;

/* ================================================================== */
/* 2. 记账表（有界、开放寻址、近似 LRU）                                */
/* ================================================================== */

/*
 * 为什么必须有界：
 *   dpkg 解包一个包会 chown 上万个文件，无界表会在几秒内吃掉几十 MB。
 * 所以表是「容量固定 + 装载率超阈值就淘汰最久未用」的。
 *
 * 淘汰策略是近似 LRU：每轮扫描全部槽位，一次挑出 last_used 最小的
 * FR_MAP_EVICT_BATCH 个驱逐。扫描是 O(cap)，但只在装载率超过
 * FR_MAP_LOAD_PERCENT 时才触发，摊还到每次插入上仍接近 O(1)。
 * 墓碑（删除标记）超过容量的 1/4 时会先做一次压实（rehash 到新数组）。
 *
 * 键的类型：
 *   FR_KEY_PATH  -- key.u.path 是 NUL 结尾的路径（已做轻量归一化）
 *   FR_KEY_INODE -- key.u.inode.dev / .ino 是 (st_dev, st_ino)
 *   FR_KEY_FD    -- key.u.fd 是文件描述符
 */
typedef enum {
    FR_KEY_PATH  = 0,
    FR_KEY_INODE = 1,
    FR_KEY_FD    = 2
} fr_key_kind;

typedef struct {
    fr_key_kind kind;
    union {
        char  *path;   /* FR_KEY_PATH：堆分配，随条目一起释放 */
        struct { dev_t dev; ino_t ino; } inode;
        int   fd;
    } u;
} fr_key;

/* 记账内容：属主 + 权限 + 哪些字段曾被显式设置过。 */
typedef struct {
    uid_t  uid;
    gid_t  gid;
    /* mode 的低 12 位（权限 + setuid/setgid/sticky）。
     * 文件类型位（S_IFMT）永远来自内核，见 fakeroot_patch_stat 的注释。 */
    mode_t mode;
    bool   uid_faked;   /* 显式 chown 过 ⇒ patch 时无条件覆盖 */
    bool   gid_faked;
    bool   mode_faked;
} fr_record;

/* ------------------------------------------------------------------ */
/* 生命周期                                                           */
/* ------------------------------------------------------------------ */

/* 创建一张表。slots 会被向上取整到 2 的幂；0 表示用 FR_MAP_DEFAULT_SLOTS。
 * 超过 FR_MAP_MAX_SLOTS 会被夹到上限。失败返回 NULL。 */
fakeroot_map *fakeroot_map_create(size_t slots);

/* 释放表本身与所有堆分配的路径键。允许传 NULL。 */
void fakeroot_map_destroy(fakeroot_map *m);

/* 清空所有条目（含墓碑），保留容量。 */
void fakeroot_map_clear(fakeroot_map *m);

/* 当前存活条目数 / 容量。指针为 NULL 时返回 0。 */
size_t fakeroot_map_count(const fakeroot_map *m);
size_t fakeroot_map_capacity(const fakeroot_map *m);

/* 关闭记账：所有插入变成 no-op、所有查询返回 FR_ENOENT。
 * 用于「只想伪装 get*id」的降级模式。 */
void fakeroot_map_set_disabled(fakeroot_map *m, bool disabled);
bool fakeroot_map_is_disabled(const fakeroot_map *m);

/* 关闭自动 LRU 淘汰：表满后 put 直接返回 FR_EFULL。默认开启。
 * 关掉它才能让「满载」这条分支在测试里被确定性地覆盖。 */
void fakeroot_map_set_eviction(fakeroot_map *m, bool enabled);
bool fakeroot_map_eviction_enabled(const fakeroot_map *m);

/* ------------------------------------------------------------------ */
/* 可观测性 / 自检（诊断用，不参与记账语义）                            */
/* ------------------------------------------------------------------ */

/*
 * 这张表**一生中**成功执行过多少次全表重哈希（fr_map_compact）。
 *
 * 为什么需要它：压实是 O(cap) 的隐式开销，装载率判据（count + tombs）
 * 与压实阈值（tombs > cap/4）都只看内部计数器 —— 一旦计数器漂了
 * （例如复用墓碑槽位时忘了 tombs--），退化会表现为「此后每次插入都
 * 重哈希」，而外部完全无从察觉。有了这个计数器，测试可以直接断言
 * 「50 次插入 0 次重哈希」，不必依赖链接期的 --wrap=calloc。
 *
 * 单调递增；fakeroot_map_clear 不清零（它统计的是历史，不是当前状态）。
 */
size_t fakeroot_map_rehash_count(const fakeroot_map *m);

/* 当前墓碑槽位数。用于断言「复用墓碑后 tombs 回落」。 */
size_t fakeroot_map_tomb_count(const fakeroot_map *m);

/* fr_map_compact 失败（ENOMEM / EFULL）的次数，同样是历史累计量。 */
size_t fakeroot_map_compact_fail_count(const fakeroot_map *m);

/*
 * 不变式自检：count / tombs 必须与槽位真实状态逐一吻合。
 * 成立返回 true；表为 NULL 时返回 false。
 */
bool fakeroot_map_check_invariants(const fakeroot_map *m);

/* ------------------------------------------------------------------ */
/* 键构造（纯函数；只有 path 版本会 malloc）                            */
/* ------------------------------------------------------------------ */

/* 用路径构造键。p 为 NULL / 空串返回 FR_EINVAL，超长返回 FR_ENAMETOOLONG。
 * 成功时 out->u.path 由 malloc 得到，所有权归调用方；
 * 交给 fakeroot_map_put() 后所有权转移给表。 */
int fakeroot_key_path(fr_key *out, const char *p);
int fakeroot_key_inode(fr_key *out, dev_t dev, ino_t ino);
int fakeroot_key_fd(fr_key *out, int fd);

/* 释放键占用的资源。纯值键是 no-op。调用后键被清零。 */
void fakeroot_key_dispose(fr_key *k);

/* 键判等。kind 不同一律不等。 */
bool fakeroot_key_equal(const fr_key *a, const fr_key *b);

/* ------------------------------------------------------------------ */
/* 增删查                                                            */
/* ------------------------------------------------------------------ */

/*
 * 插入或覆盖。k 的**所有权转移**给表：无论成功失败都由本函数负责释放，
 * 调用方不需要（也不允许）再 dispose 它。
 * 成功 FR_OK；表满且无法淘汰 FR_EFULL；内存不足 FR_ENOMEM。
 */
int fakeroot_map_put(fakeroot_map *m, fr_key k, const fr_record *rec);

/* 查找。命中 FR_OK 并写入 *out；未命中 FR_ENOENT。
 * 命中会刷新该条目的时戳（近似 LRU 的核心）。 */
int fakeroot_map_get(fakeroot_map *m, const fr_key *k, fr_record *out);

/* 只判存在，不取内容，但同样刷新时戳。 */
bool fakeroot_map_has(fakeroot_map *m, const fr_key *k);

/* 删除。删掉 FR_OK，本来就不在 FR_ENOENT。
 *
 * ⚠ 所有权与 fakeroot_map_put **不同**：k 是 const 指针，本函数只读取它
 * 做探测，**不接管**、也不释放它。它释放的是**表内**那一份键
 * （fr_slot_release ⇒ fakeroot_key_dispose(&m->slots[idx].key)）。
 * 调用方对 k 仍然负全责 —— 由 fakeroot_key_path() 造出来的 k 必须
 * 由调用方 fakeroot_key_dispose()。不 dispose 就是每次调用漏一份路径副本
 * （命中漏一份，未命中同样漏一份）。 */
int fakeroot_map_remove(fakeroot_map *m, const fr_key *k);

/* 强制淘汰 n 个最久未使用的条目，返回实际淘汰数。 */
size_t fakeroot_map_evict_lru(fakeroot_map *m, size_t n);

/* ------------------------------------------------------------------ */
/* 便捷封装：属主 / 权限记账                                            */
/* ------------------------------------------------------------------ */

/* 记一条「这个路径属于 uid:gid」。传 (uid_t)-1 表示该字段不变。
 * 同时写 by_path（若有路径）与 by_inode（若 dev/ino 非零）。 */
int fakeroot_record_owner_path(fakeroot_state *fs, const char *p,
                               uid_t uid, gid_t gid);
int fakeroot_record_owner_inode(fakeroot_state *fs, dev_t dev, ino_t ino,
                                uid_t uid, gid_t gid);
int fakeroot_record_owner_fd(fakeroot_state *fs, int fd,
                             uid_t uid, gid_t gid);

/* 记一条权限。mode 只取低 12 位。 */
int fakeroot_record_mode_path(fakeroot_state *fs, const char *p, mode_t mode);
int fakeroot_record_mode_inode(fakeroot_state *fs, dev_t dev, ino_t ino,
                               mode_t mode);
int fakeroot_record_mode_fd(fakeroot_state *fs, int fd, mode_t mode);

/* 查一条记录：先按 dev+ino（最可靠），再按路径。
 * dev 与 ino 同时为 0 时跳过 inode 查询；p 为 NULL 时跳过路径查询。
 * 命中 FR_OK，未命中 FR_ENOENT。 */
int fakeroot_lookup(fakeroot_state *fs, const char *p,
                    dev_t dev, ino_t ino, fr_record *out);
int fakeroot_lookup_fd(fakeroot_state *fs, int fd, fr_record *out);

/*
 * 记一条「刚被创建」。proot 在 open(O_CREAT)/mkdir/mknod 之后都会写
 * meta 文件（USERLAND 分支的 open.c:17-95 / mk.c:12-44），目的只有一个：
 * 让**新建的文件**立刻表现为「假身份创建」，而不是「内核真实 uid 创建」。
 *
 * 这一步是 issue #12 的另一半：没有它，dpkg 解包出来的新文件属主是
 * Android 应用 uid，即便 stat 的启发式能把它改写成 0，只要用户显式
 * chown 过某个文件、记账表里有了别的值，语义就会割裂。
 * 有了它，「新建 ⇒ 属于假身份」是一条明确的记录，而不是靠猜。
 *
 * 同时把 mode 记下来（新建文件的权限位）。
 * uid/gid 传 (uid_t)-1/(gid_t)-1 表示不清除已有记录里的属主。
 */
int fakeroot_record_create_path(fakeroot_state *fs, const char *p, mode_t mode,
                                uid_t uid, gid_t gid);

/* 删除记账：文件被 unlink/rename 时调用，避免陈旧条目。 */
int fakeroot_forget_path(fakeroot_state *fs, const char *p);
int fakeroot_forget_inode(fakeroot_state *fs, dev_t dev, ino_t ino);

/* ================================================================== */
/* 3. stat 结果补丁（纯逻辑，无 syscall）                               */
/* ================================================================== */

/*
 * 补丁规则（三级优先级，从高到低）：
 *
 *   1. 记账命中 ⇒ 用记录覆盖 st_uid/st_gid/st_mode。
 *      mode 的合成严格照抄 proot stat.c:125：
 *          st_mode = rec.mode | (内核 st_mode & (S_IFMT | 07000))
 *      即「权限位取记账，文件类型 + setuid/setgid/sticky 取内核」。
 *      只覆盖 uid_faked/gid_faked/mode_faked 为真的字段。
 *
 *   2. 记账未命中且 fs->enabled ⇒ 按 fs->heuristic 做启发式（默认 OWNER）：
 *          st_uid == real_uid ⇒ st_uid = euid
 *          st_gid == real_gid ⇒ st_gid = egid
 *      这是官方 proroot 的活体行为：内核属主是 Android 应用 uid 的文件，
 *      在容器里一律读成 0。
 *
 *   3. 其余情况一律不动 —— 特别是 st_ino / st_dev / st_nlink / 时间戳。
 *
 * ★ 为什么不用 st_ino 高位编码（任务书第 7 问，完整权衡见 REPORT.md §4）★
 *   proot **并没有**做 st_ino 编码。它的 fake_id0 用两种机制：
 *     (a) 磁盘 sidecar 文件 `<dir>/.proot-meta-file.<name>`（USERLAND 构建）；
 *     (b) 同一进程内的 Config（ptrace 构建，天然跨 fork 但只覆盖自己的 tracee）。
 *   本模块选进程内表，理由是 l2s 子系统与 dpkg 数据库都以
 *   st_ino 为关联键，篡改高位会让「同一个文件」在两个子系统里算出不同键。
 *   跨 exec 的丢失用「环境变量重注入 + BXROOT_META_DIR sidecar」兜底，
 *   见 REPORT.md §4 的三方案对比表。
 *
 * 所有 patch_* 都是纯函数：只读写参数指向的结构体和 fs，绝不调用 syscall。
 * fs 为 NULL 或 fs->enabled == false 时立即返回，不做任何修改。
 */

void fakeroot_patch_stat(struct stat *st, fakeroot_state *fs);
void fakeroot_patch_stat64(struct stat64 *st, fakeroot_state *fs);

/*
 * statx 的补丁。与 stat 的差别：
 *   - 每个字段都有一个 stx_mask 位，没置位表示内核没填这个字段，不能碰；
 *   - proot stat.c:164-175 用 stx_mask & STATX_UID / STATX_GID 做闸门；
 *   - 要改 stx_mode 就必须同时确保 STATX_MODE 已置位，否则调用方会以为
 *     该字段无效 —— 我们的覆盖等于凭空造数据。
 *
 * ⚠ 上游 stat.c:171 有一处笔误：`if (stx_gid == getuid())`，gid 拿去和
 *   getuid() 比了。本实现按语义修正为 real_gid，见 REPORT.md §6。
 */
void fakeroot_patch_statx(struct statx *stx, fakeroot_state *fs);

/*
 * 扩展版：调用方可以额外传入「按路径预先查到的记录」与 fd。
 * 钩子层用这个：chown("a/b") 记的是路径键，而 struct stat 里只有
 * dev+ino，所以路径那一路必须由调用方查好再传进来。
 * rec 为 NULL 表示没有预取记录；fd < 0 表示不查 fd 表。
 */
void fakeroot_patch_stat_ex(struct stat *st, fakeroot_state *fs,
                            const fr_record *rec, int fd);
void fakeroot_patch_stat64_ex(struct stat64 *st, fakeroot_state *fs,
                              const fr_record *rec, int fd);
void fakeroot_patch_statx_ex(struct statx *stx, fakeroot_state *fs,
                             const fr_record *rec, int fd);

/* 不带状态的便捷版本：只做规则 2 的启发式。 */
void fakeroot_patch_stat_simple(struct stat *st, uid_t real_uid, uid_t fake_uid,
                                gid_t real_gid, gid_t fake_gid);

/* ================================================================== */
/* 4. access(2) 仿真                                                   */
/* ================================================================== */

/*
 * 任务书要求「查清 proot 的确切语义再照做」。proot 的分支：
 *
 *   access.c:35-36  F_OK 直接返回 0（除非前面 check_dir_perms 已经拒了）。
 *   access.c:42-48  把 R_OK/W_OK/X_OK 折成 3 位掩码。
 *   helper_functions.c:187-192
 *                   emulated_uid == owner || emulated_uid == 0 ⇒ 用 owner 权限位
 *                   emulated_gid == group            ⇒ 用 group 权限位
 *                   否则                              ⇒ 用 other 权限位
 *   helper_functions.c:207-208
 *                   emulated_uid == 0 ⇒ omode |= 6，即 **root 额外获得 r+w**，
 *                   但**不额外获得 x**。
 *   access.c:51-53  掩码不满足 ⇒ -EACCES，否则放行。
 *
 * 也就是说 proot 的规则是（这段注释就是本函数的规格）：
 *   1. 假 uid 为 0（或等于文件属主）时按 owner 位判；否则按 group/other 位判。
 *      注意假 uid 为 0 时**永远走 owner 分支**，与文件真实属主无关。
 *   2. 假 uid 为 0 时把 r 和 w 位强制打开（`|= 6`）。
 *   3. **x 位不因为 uid==0 而放开**，proot 也不对目录做特殊处理。
 *      这与 Linux 内核的 CAP_DAC_OVERRIDE 语义不同（内核里 root 对
 *      目录恒可搜索，对普通文件也可绕过 x 检查）。本实现选择**照抄 proot**
 *      并把这个分歧显式写进 REPORT.md §5。
 *      理由：在内核里我们本来就没有 CAP_DAC_OVERRIDE（真实身份是 Android
 *      应用 uid），伪装得比 proot 更宽松只会制造「我说能开、真 open 又失败」
 *      的矛盾；严格一点永远不会放出内核随后会拒绝的许可。
 *
 * 另外：本函数只回答「按伪装身份该不该放行」。钩子层必须把它和真实
 * access() 的结果用 fakeroot_access_override() 组合，规则是
 * 「真实成功 ⇒ 成功；真实失败但模型放行 ⇒ 伪造成功；否则透传失败」。
 * 这与 proot 的 handle_perm_err_exit_end（fake_id0.c:535-559）
 * 「只覆盖错误、绝不凭空造错误」是同一个哲学。
 *
 * 参数：
 *   st       -- 已经打过补丁的 stat 结果（这样判决才能反映 chown 记账）
 *   mode     -- access(2) 的 mode 参数
 *   st_valid -- st 是否有效（真实 stat 成功）。false ⇒ 保守判 GRANTED，
 *               让真实 access() 的 errno（通常是 ENOENT）透出去。
 *   as_root  -- 假 uid 是否为 0
 */
fr_access_verdict fakeroot_check_access(const struct stat *st, int mode,
                                        bool st_valid, bool as_root);

/*
 * 组合真实结果与模型判决。real_errno 是真实 access() 失败时的 errno。
 * 返回 true 表示钩子应吞掉错误并返回 0。
 */
bool fakeroot_access_override(int real_errno, fr_access_verdict model);

/* 给定 (文件 mode, 是否属主, 是否同组, 是否 root)，算出可用的权限三元组。
 * 返回值 0..7。单独导出是为了让测试能逐条覆盖 proot 的 omode 规则。 */
int fakeroot_permission_bits(mode_t file_mode, bool is_owner, bool in_group,
                             bool as_root);

/* ================================================================== */
/* 5. 身份变更状态机（纯逻辑，不下发内核）                              */
/* ================================================================== */

/* 把 fs 初始化成「默认的 fakeroot 身份」：uid/gid 全 0，caps 活跃。 */
void fakeroot_state_init(fakeroot_state *fs);

/* 记录真实身份（钩子层用 syscall() 直接读，不经任何 hook）。 */
void fakeroot_state_set_real_ids(fakeroot_state *fs, uid_t ruid, uid_t euid,
                                 gid_t rgid, gid_t egid);

/* 打开/关闭伪装。打开时把假身份重置为全 0。 */
void fakeroot_state_set_enabled(fakeroot_state *fs, bool enabled);

/*
 * 下面这组是 setuid 家族的完整仿真，与 fake_id0.c:102-291 逐行对应。
 * 返回值：FR_OK 表示成功（并已更新 fs）；FR_EPERM 表示应返回 -EPERM 且
 * 状态不变。**它们都绝不调用真正的 setuid(2)** —— 这正是 GAP-ANALYSIS
 * 里「提权被吞掉」的要求，也是 fakeroot 能在非 root 进程里工作的前提。
 */
int fakeroot_setuid(fakeroot_state *fs, uid_t uid);
int fakeroot_setgid(fakeroot_state *fs, gid_t gid);
int fakeroot_setreuid(fakeroot_state *fs, uid_t r, uid_t e);
int fakeroot_setregid(fakeroot_state *fs, gid_t r, gid_t e);
int fakeroot_setresuid(fakeroot_state *fs, uid_t r, uid_t e, uid_t s);
int fakeroot_setresgid(fakeroot_state *fs, gid_t r, gid_t e, gid_t s);
/* setfsuid/setfsgid 返回**旧值**（man setfsuid）；失败时也返回当前值。 */
uid_t fakeroot_setfsuid(fakeroot_state *fs, uid_t fsuid);
gid_t fakeroot_setfsgid(fakeroot_state *fs, gid_t fsgid);

/* setgroups(2)：list 为 NULL 且 n == 0 表示清空。n > FR_NGROUPS_MAX → FR_EINVAL。 */
int fakeroot_setgroups(fakeroot_state *fs, const gid_t *list, size_t n);
/* getgroups(2) 的纯逻辑版本：把 fs 里的组写进 list（最多 size 个），
 * 返回实际写入数；size == 0 时返回总数；size 不足时返回 FR_EINVAL。 */
int fakeroot_getgroups(const fakeroot_state *fs, gid_t *list, size_t size);

/* prctl(PR_SET_KEEPCAPS) / PR_GET_KEEPCAPS 的镜像。 */
void fakeroot_set_keepcaps(fakeroot_state *fs, bool on);
bool fakeroot_get_keepcaps(const fakeroot_state *fs);

/*
 * chown 的权限闸门（chown.c:81-92）：
 *   euid == 0        ⇒ 放行，可改属主与属组
 *   euid == 文件属主 ⇒ 只能改组；owner 被强制回原值
 *   否则             ⇒ FR_EPERM
 * out_uid / out_gid 是**实际要记入记账表的值**（可能因为「只能改组」
 * 被改写）。请求值传 (uid_t)-1 表示「该字段不变」。二者可为 NULL。
 */
int fakeroot_gate_chown(const fakeroot_state *fs, const fr_record *cur,
                        uid_t req_uid, gid_t req_gid,
                        uid_t *out_uid, gid_t *out_gid);

/* chmod 的闸门（chmod.c:50-51）：非属主且非 root ⇒ FR_EPERM。 */
int fakeroot_gate_chmod(const fakeroot_state *fs, const fr_record *cur);

/*
 * 组合「真实调用结果」与「闸门结论」，决定钩子的最终动作。
 *   real_ret == 0                ⇒ 透传成功（真实调用已经生效）
 *   real_errno ∉ {EPERM,EACCES}  ⇒ 透传真实错误（ENOENT/EROFS… 不该被吞）
 *   gate == FR_EPERM             ⇒ 透传（并保证 errno = EPERM）
 *   否则                         ⇒ FR_CHOWN_FAKE_OK
 * 这就是 GAP-ANALYSIS §6.1 第 3 条「先查真实调用，失败才记账并返回 0」。
 */
fr_chown_action fakeroot_chown_action(int real_ret, int real_errno,
                                      int gate_ret);

/* ================================================================== */
/* 6. 全局状态与钩子层（FAKEROOT_PURE_LOGIC 下不声明）                  */
/* ================================================================== */
#ifndef FAKEROOT_PURE_LOGIC

/* 进程级单例。钩子层与 preload.c 共用这一个。 */
extern fakeroot_state g_fakeroot;

/*
 * 初始化。幂等，可重复调用。会：
 *   - 从环境变量 BXROOT_FAKEROOT 决定是否启用（与 preload.c:112-113 同源）；
 *   - 可选地读 BXROOT_FAKE_UID / BXROOT_FAKE_GID 覆盖默认的 0；
 *   - 用 syscall() 直接读真实身份（绕过自身 hook，无递归）；
 *   - 建好两张记账表。
 * 成功返回 FR_OK；失败返回负值（此时 g_fakeroot.enabled 一定是 false，
 * 且所有钩子都会退化成纯透传）。
 */
int fakeroot_hook_init(void);

/* 构造函数：库被 dlopen/LD_PRELOAD 时自动执行。幂等。
 * preload.c 也可以显式调用 fakeroot_hook_init()，两者只会初始化一次。 */
__attribute__((constructor))
void fakeroot_ctor(void);

/*
 * ★ 给 preload.c 的集成入口 ★
 *
 * preload.c 已经钩了 open/open64/openat/openat64 做路径翻译，所以
 * **不应该**再把 fakeroot.c 里的 open 钩子链进去（会有两个同名符号）。
 * 正确做法是在 preload.c 现有的 open 钩子里，真实调用成功之后插一行：
 *
 *     if (ret >= 0)
 *         (void)fakeroot_hook_record_create(translated, flags, mode);
 *
 * 传入的路径应当是**真实内核路径**（也就是 translate_path 之后的那条），
 * 因为随后 stat 补丁查表时用的也是翻译后的路径。
 * 完整步骤见 INTEGRATION.md §3。
 *
 * 返回 0 表示记了一条；-1 表示不需要记（fakeroot 未启用 / 没有 O_CREAT）。
 */
int fakeroot_hook_record_create(const char *path, int flags, mode_t mode);

/*
 * 钩子层其余入口（供 preload.c 直接转发，如果不想把本文件整个链进去）。
 * 每个都是「能直接当 LD_PRELOAD 符号用」的完整实现。
 * 完整清单见 fakeroot.c 末尾的 §7。
 */

#endif /* FAKEROOT_PURE_LOGIC */

#ifdef __cplusplus
}
#endif

#endif /* FAKEROOT_H */
