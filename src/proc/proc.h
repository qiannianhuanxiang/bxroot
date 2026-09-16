/*
 * proc.h -- bxroot 的进程管理层（GAP-ANALYSIS D4 域）
 *
 * 背景
 * ----
 * 克隆版只 hook 了 `execve`/`execvpe` 两个符号，GAP-ANALYSIS 判定为 P0 阻断级：
 * 子进程要么失去容器身份（envp 被调用方替换掉），要么创建路径完全不经过钩子
 * （`posix_spawn` / `system` / `popen`），要么信号能打到容器外（`kill` 无白名单）。
 *
 * 本文件的分层（与 fakeroot.h / l2s-runtime.h 同一套方法论）
 * ---------------------------------------------------------
 *   ┌────────────────────────────────────────────────────────────────┐
 *   │ 第 1 层：纯逻辑（无 syscall、无 dlsym、可单测）                │
 *   │   px_ledger        pid 账本（有界开放寻址 + 墓碑 + 近似 LRU）  │
 *   │   px_env_*         envp 重建与 LD_PRELOAD 合并                 │
 *   │   px_plan_argv     argv 路径翻译判定与翻译计划                 │
 *   │   px_check_kill    kill 越界判定（安全边界）                   │
 *   │   px_forkguard     atfork 三件套的状态机                       │
 *   └────────────────────────────────────────────────────────────────┘
 *   ┌────────────────────────────────────────────────────────────────┐
 *   │ 第 2 层：钩子层（LD_PRELOAD，只在 px_pure_logic == 0 时编译）  │
 *   │   posix_spawn/p、exec 全家、fork/vfork、system/popen、kill 家族 │
 *   │   以及 posix_spawn_file_actions_addopen 的路径翻译              │
 *   └────────────────────────────────────────────────────────────────┘
 * 只要纯逻辑的测试程序请定义 PX_PURE_LOGIC 后再 include 本头文件。
 *
 * 为什么所有 FS/系统调用都要注入
 * ------------------------------
 * 本容器无法端到端验证 LD_PRELOAD（外层 proot 会吞掉注入，见
 * `_shared/容器内测试不可信.md`）。只有「可注入的纯逻辑」才测得动，
 * 因此 pid 账本、envp 重建、argv 判定、kill 判定一律走注入式 ops。
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef PROC_H
#define PROC_H

/*
 * 必须在任何系统头文件之前定义：`struct stat64`/`S_ISLNK` 之类需要它，
 * 而 `posix_spawn_file_actions_*` 需要 _GNU_SOURCE 或 _POSIX_C_SOURCE>=200112。
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*
 * 纯逻辑 / 钩子层的编译开关，**取值开关**（不是「定义即开」）。
 *
 *   -DPX_PURE_LOGIC=1  → 只编纯逻辑（单测、任何不带 libdl 的环境）★ 默认
 *   -DPX_PURE_LOGIC=0  → 连钩子层一起编（preload.c 的集成构建）
 *
 * 默认取 1 是刻意的：忘记传开关时应当得到「可测的小块」，
 * 而不是「一个需要 libdl、需要 spawn.h、还会导出 execve 符号的大块」——
 * 后者会让单测链接到一个自己也定义 execve 的目标文件上，症状诡异。
 *
 * 默认值必须在这里落定，且 proc.c 里**不重复定义**：
 * 以前版本在两边各写一套（头文件用 `!defined`、实现用 `!值`），
 * 结论不一致 —— 默认构建下头文件声明了钩子层原型而实现里没有定义，
 * 用了就是链接错误。
 */
#ifndef PX_PURE_LOGIC
#define PX_PURE_LOGIC 1
#endif

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================== */
/* 0. 常量与错误码                                                     */
/* ================================================================== */

/* 单条路径的缓冲上限（含结尾 NUL）。与 Linux PATH_MAX 一致。 */
#define PX_PATH_MAX 4096

/*
 * envp 条目数上限。
 *
 * 有界的理由与 fakeroot 的记账表相同：`execve` 是热路径，而 envp 由调用方
 * 提供，理论上可以是一个无限长的数组（甚至是未终止的畸形数组）。
 * 我们必须在**不信任调用方**的前提下工作，所以扫描时自带上限。
 */
#define PX_ENVP_MAX 4096

/* 单条环境变量（含名字与 '='）的长度上限。 */
#define PX_ENV_ENTRY_MAX 8192

/* LD_PRELOAD 合并结果的长度上限。 */
#define PX_PRELOAD_MAX 16384

/* 一次 argv 翻译最多改写多少条参数。 */
#define PX_ARGV_MAX 4096

/* pid 账本默认槽位数，必须是 2 的幂。 */
#define PX_LEDGER_DEFAULT_SLOTS 256u

/* pid 账本槽位硬上限（pid_max 默认 4194304，但容器里远用不到这么多）。 */
#define PX_LEDGER_MAX_SLOTS (1u << 22)

/* 装载率阈值（百分比），超过就先淘汰/扩容。 */
#define PX_LEDGER_LOAD_PERCENT 75u

/* 一次淘汰扫描最多驱逐多少个条目。 */
#define PX_LEDGER_EVICT_BATCH 16u

/* 纯逻辑函数的返回码。 */
enum {
    PX_OK        =  0,
    PX_ENOENT    = -1,   /* 表里没有该条目                        */
    PX_ENOMEM    = -2,   /* 分配失败或容量非法                    */
    PX_EFULL     = -3,   /* 表已满且无淘汰能力                    */
    PX_EINVAL    = -4,   /* 参数非法                              */
    PX_ETOOLONG  = -5,   /* 路径/条目超长                         */
    PX_EPERM     = -6,   /* 权限不足（kill 越界）                 */
    PX_ENOSPC    = -7    /* 输出缓冲不足                          */
};

/* ------------------------------------------------------------------ */
/* 注入的操作表                                                        */
/* ------------------------------------------------------------------ */

/*
 * 分配器注入。
 *
 * 存在的唯一理由是**故障注入**：`PX_ENOMEM` 分支在生产里几乎不可达，
 * 但一旦可达（Android 低内存杀后台）就是「半残的账本 + 静默失效」，
 * 与 fakeroot 记账表建不起来时的危险性同类。用注入的分配器才测得到。
 * 传 NULL 时全部回落 libc。
 */
typedef struct {
    /*
     * `ud` 是必须的，不是装饰。
     *
     * px_bump（无分配分配器）需要携带自己的状态指针。没有 ud 时唯一的
     * 替代是进程级全局变量 —— 而 vfork 子进程与父进程共享地址空间，
     * 全局可变状态在那里是危险的。带 ud 后分配器是纯函数式的，
     * 可以任意嵌套、可以并发、可以在共享地址空间里安全使用。
     */
    void *ud;
    void *(*malloc)(void *ud, size_t size);
    void *(*calloc)(void *ud, size_t nmemb, size_t size);
    void  (*free)(void *ud, void *p);
} px_alloc;

/* 进程/信号相关的真实系统调用注入（纯逻辑层不直接调）。 */
typedef struct {
    pid_t (*getpid)(void);
    pid_t (*getppid)(void);
    pid_t (*getpgrp)(void);
    int   (*kill)(pid_t pid, int sig);
} px_sysops;

/* ================================================================== */
/* 1. pid 账本                                                         */
/* ================================================================== */

/*
 * 条目的「性质」。
 *
 * `PX_ENTRY_PGID` 与进程条目的区别只在 kill 判定：`kill(-pgid, sig)` 打的是
 * 进程组。我们没有 pid 命名空间，所以进程组号就是宿主 pgid，必须靠「这个
 * pgid 是不是我们某个子进程的 pid」来判断（子进程 `setpgid(0,0)` 之后
 * pgid == pid 是最常见的形态）。
 */
typedef enum {
    PX_ENTRY_PID  = 0,
    PX_ENTRY_PGID = 1
} px_entry_kind;

/*
 * 条目的「生死」。
 *
 * 这个字段是 kill 越界防护的**核心**，不是装饰：
 *   PX_LIVE   -- 我们自己 fork/spawn 出来、还没 wait 掉的进程，信号必须放行；
 *   PX_REAPED -- 已经 wait 掉的 pid。**危险**：宿主可能已经把这个 pid
 *                回收给了别的进程，此时放行等于把信号打进宿主的无辜进程。
 *                所以 reaped 一律拒绝 —— 见 px_check_kill 的说明。
 */
typedef enum {
    PX_LIVE   = 0,
    PX_REAPED = 1
} px_life;

typedef struct {
    pid_t         pid;
    pid_t         ppid;        /* 创建者；用于「允许给父进程发信号」判定 */
    px_entry_kind kind;
    px_life       life;
    uint32_t      tag;         /* 创建来源（PX_TAG_*），仅用于诊断 */
} px_procinfo;

/* 创建来源标签，便于在报告与日志里区分。 */
#define PX_TAG_UNKNOWN   0u
#define PX_TAG_FORK      1u
#define PX_TAG_SPAWN     2u
#define PX_TAG_EXEC      3u
#define PX_TAG_SYSTEM    4u
#define PX_TAG_POPEN     5u
#define PX_TAG_SELF      6u

typedef struct px_ledger px_ledger;

/*
 * 创建账本。slots == 0 用默认值；向上取整到 2 的幂；超过硬上限则截断。
 * alloc 为 NULL 时用 libc。失败返回 NULL。
 */
px_ledger *px_ledger_create(size_t slots, const px_alloc *alloc);

/* 销毁（幂等；NULL 安全）。 */
void px_ledger_destroy(px_ledger *l);

/* 清空所有条目，保留容量。 */
void px_ledger_clear(px_ledger *l);

/*
 * 记账一个进程。重复 pid 视为「刷新」（更新 ppid/life/tag），返回 PX_OK。
 *
 * 容量不足时：优先扩容（扩容会把 reaped 条目当可丢弃的）；
 * 扩不动再淘汰最久未用的 **reaped** 条目；若全是 live 条目则返回 PX_EFULL。
 * **绝不淘汰 live 条目** —— 淘汰 live 会把可 kill 的子进程变成不可 kill，
 * 那是功能缺陷；而淘汰 reaped 只是少了一层保护（且保护本就该拒绝）。
 */
int px_ledger_add(px_ledger *l, pid_t pid, pid_t ppid, uint32_t tag);

/* 追加一条进程组条目（kind = PX_ENTRY_PGID）。 */
int px_ledger_add_pgid(px_ledger *l, pid_t pgid, uint32_t tag);

/* 查询：存在返回 PX_OK 并（可选）填 *out；不存在返回 PX_ENOENT。 */
int px_ledger_get(const px_ledger *l, pid_t pid, px_entry_kind kind,
                  px_procinfo *out);

/* 存在性判定。 */
int px_ledger_has(const px_ledger *l, pid_t pid, px_entry_kind kind);

/* 标记为已回收（wait 掉之后调用）。条目保留，用于 pid 复用防护。
 * 返回 PX_OK；不存在返回 PX_ENOENT。 */
int px_ledger_reap(px_ledger *l, pid_t pid);

/* 彻底删除条目。 */
int px_ledger_remove(px_ledger *l, pid_t pid, px_entry_kind kind);

/* 诊断计数。 */
size_t px_ledger_count(const px_ledger *l);
size_t px_ledger_capacity(const px_ledger *l);
size_t px_ledger_live_count(const px_ledger *l);
size_t px_ledger_reaped_count(const px_ledger *l);

/* 全局开关：关掉后 add 变 no-op、查询一律 PX_ENOENT、判定回落放行。 */
void px_ledger_set_disabled(px_ledger *l, int disabled);
int  px_ledger_is_disabled(const px_ledger *l);

/* 是否允许自动淘汰。关掉后表满即 PX_EFULL，便于测试确定性地打满。 */
void px_ledger_set_eviction(px_ledger *l, int enabled);
int  px_ledger_eviction_enabled(const px_ledger *l);

/* 显式淘汰 n 个最久未用的 **reaped** 条目，返回实际淘汰数。 */
size_t px_ledger_evict(px_ledger *l, size_t n);

/* ================================================================== */
/* 2. envp 重建（LD_PRELOAD / BXROOT_* 注入）                          */
/* ================================================================== */

/*
 * 为什么必须做这件事（本项目最容易被忽略的泄漏点）
 * ------------------------------------------------
 * `execve(path, argv, envp)` 的 envp 是**调用方完全掌控**的：它可以把环境
 * 换成一个全新的数组，于是 `LD_PRELOAD` 不复存在，子进程完全没有钩子 ——
 * 它看到宿主 `/`、stat 返回真实属主、l2s 消失，而且**没有任何报错**。
 *
 * 已实证（见 exp/EVIDENCE.md E6）：
 *     node -e "execFileSync('/usr/bin/env',[],{env:{FOO:'1'}})"
 *     → 子进程环境只有 FOO=1 与外层注入的几个变量，不含 LD_PRELOAD
 *
 * 所以工程上的结论是：**只要经过我们的 exec/spawn，就必须重建 envp。**
 */

/*
 * 强制条目的写入方式。
 *
 * ★ PX_ENV_MERGE_PRELOAD 的存在是一个实测教训 ★
 * 最初版本把 LD_PRELOAD 当普通强制变量写：结果是在**值层面覆盖**，
 * guest 自己设的 `LD_PRELOAD=/guest.so` 被整个丢掉。而 GAP-ANALYSIS §6.3
 * 明确要求「要合并而非覆盖，否则会破坏 guest 自己的 preload」。
 *
 * 症状会很隐蔽：容器自己的钩子工作正常，但 guest 依赖的 preload 库
 * （malloc 调试器、asan、性能探针）静默消失 —— 表现为「某个第三方工具
 * 在容器里行为诡异」，排查方向会完全跑偏。测试 K3 在真实内核上钉住它。
 */
typedef enum {
    PX_ENV_SET           = 0,  /* 直接覆盖 */
    PX_ENV_MERGE_PRELOAD = 1   /* 与输入环境里的同名值合并（ours 在前） */
} px_env_mode;

/* 一条「强制写入」的环境变量。 */
typedef struct {
    const char *name;    /* 不含 '='；NULL 表示数组结束 */
    const char *value;   /* 允许为 NULL，等价于空串 */
    px_env_mode mode;    /* 见 px_env_mode；0 == PX_ENV_SET */
} px_env_kv;

/* 重建策略。 */
typedef struct {
    const px_env_kv *forced;      /* 强制写入（覆盖同名的原有条目） */
    size_t           forced_n;
    const char *const *drop;      /* 需要剔除的名字（不含 '='） */
    size_t           drop_n;
    size_t           max_entries; /* 结果条数上限；0 用 PX_ENVP_MAX */
} px_envpolicy;

/*
 * 重建结果。
 *
 * 内存布局刻意做成「一整块 buf + 偏移表 + 指针数组」：execve 之后我们无法
 * 回收内存（成功时进程映像已被替换），所以只需要一次分配、失败时一次释放
 * 即可，不必逐条 malloc 再逐条 free（那会在失败路径上留下泄漏）。
 *
 * ★ 为什么要 `offs` 而不是直接把指针写进 `v` ★
 * buf 会随条目增加而**扩容**（malloc + memcpy + free 换一块更大的）。
 * 若 `v[i]` 直接存 buf 内的地址，扩容一次就让**此前所有指针全部悬空** ——
 * 这是本项目第一版实现里真实存在过的缺陷，由 T-E 组用例（条目数越过
 * 扩容边界）钉住。所以构建期只存偏移，收尾时一次性分配 `v` 再换算成指针。
 */
typedef struct {
    char   *buf;      /* 后备存储，按 '\0' 串接 */
    size_t  buf_len;
    size_t  buf_cap;
    char  **v;        /* 以 NULL 结尾的指针数组（收尾时才分配） */
    size_t  n;
    size_t  cap;
    size_t *offs;     /* 内部：每条在 buf 里的字节偏移 */
    const px_alloc *alloc;
} px_envout;

/*
 * 用 in_envp（可为 NULL，等价于空环境）与策略 pol 重建环境。
 *
 * 返回 PX_OK / PX_ENOMEM / PX_ENOSPC / PX_EINVAL。
 * 成功后必须用 px_env_dispose 释放（除非已经 exec 成功）。
 *
 * 语义要点：
 *   - in_envp 为 NULL 时**不**回落到进程 environ —— 那是钩子层的决定，
 *     纯逻辑层不做隐式兜底，否则测试无法构造「空环境」这个用例。
 *   - 同名的强制变量**覆盖**原条目，且**位置**保持在最后一次出现处之后
 *     追加，不做原地替换（原地替换需要变长写入，反而更复杂）。
 *   - 原 envp 里重复的变量名保留（POSIX 允许），但强制变量只写一次。
 */
int px_env_build(const char *const *in_envp, const px_envpolicy *pol,
                 px_envout *out, const px_alloc *alloc);

/* 释放 px_env_build 的产物。NULL 安全、幂等。 */
void px_env_dispose(px_envout *out);

/*
 * 合并 LD_PRELOAD。
 *
 * ours 放在**最前面**，理由不是审美：LD_PRELOAD 的符号查找按列表顺序进行，
 * 谁的库在前谁的同名符号先被解析。把我们的库放后面，一旦 guest 自己的
 * preload 库里也定义了 `open`/`stat`（很常见，例如它自带的 malloc 调试器），
 * 我们的翻译钩子就会被**完全遮蔽**，而 guest 库不会主动 RTLD_NEXT 回我们。
 * 放最前面则我们的钩子先跑，它内部用 `dlsym(RTLD_NEXT)` 继续链到 guest 库，
 * 两边都不丢。
 *
 * 去重按「路径全等」与「basename 相等」双重判定 —— 同一个库用不同拼写
 * （相对/绝对）重复出现在 LD_PRELOAD 里会让 ld.so 重复加载，进而让
 * 构造函数跑两次。
 *
 * existing 为 NULL/空时结果就是 ours。返回 PX_OK / PX_ENOSPC。
 */
int px_merge_preload(const char *existing, const char *ours,
                     char *out, size_t outsz);

/*
 * 判断一条 "NAME=VALUE" 条目的名字是否等于 name。
 * entry 不合法（无 '='）时返回 0。
 */
int px_env_entry_matches(const char *entry, const char *name);

/* 从环境数组里取值（最后一次出现者胜出）。找到返回指针（指向 '=' 之后），
 * 否则返回 NULL。 */
const char *px_env_lookup(const char *const *envp, const char *name);

/* ================================================================== */
/* 3. argv 路径翻译判定                                                */
/* ================================================================== */

/*
 * 为什么不能「把所有参数都当路径翻译」
 * ----------------------------------
 * argv 里绝大多数条目**不是**路径。典型反例：
 *     grep  /etc/passwd  /etc/hosts     ← 第 2 个是路径，第 1 个是**模式**
 *     sed   's!/a!/b!'   file
 *     node  -e "require('/x')"          ← 路径藏在代码串里，翻了就是改语义
 * 盲目翻译会把 `grep /etc/passwd` 的模式改成 `<rootfs>/etc/passwd`，
 * 于是匹配永远不中 —— **静默的功能破坏**。
 *
 * 因此判定规则刻意保守：
 *   1. 只有**绝对路径**（首字符 '/'）才是翻译候选；相对路径与裸名一律保留。
 *      （相对路径是相对于子进程 cwd 的，而 cwd 已经由 chdir 钩子翻译过，
 *        再翻一次就是二次加前缀。）
 *   2. 默认只翻译 **argv[0]**。
 *      argv[0] 是「被执行的程序名」，程序会拿它做 applet 选择（busybox）、
 *      做 /proc/self/cmdline 自省、做错误信息。Node/python 都会把完整路径
 *      放进 argv[0]，翻译后子进程看到的是宿主路径 —— 这是**已知且可接受**的
 *      泄漏，与官方 proroot 同构（它也只做 resolve_child_argv0）。
 *      不翻 argv[0] 的代价更大：busybox 之类的程序会按 argv[0] 找 applet，
 *      路径不对就找不到。
 *   3. 其余参数只有在**显式登记**为「取路径的选项」时才翻译，默认不翻。
 *      这是有意的：宁可少翻（表现为程序自己再去 open 时被 open 钩子翻），
 *      不可多翻（表现为语义被改坏且无迹可循）。
 */
typedef enum {
    PX_ARG_KEEP       = 0,  /* 原样保留 */
    PX_ARG_TRANSLATE  = 1,  /* 是绝对路径，应翻译 */
    PX_ARG_ALREADY    = 2   /* 已带 rootfs 前缀（或已 bind 展开），必须原样保留 */
} px_arg_verdict;

/*
 * argv 翻译策略。
 *
 * 把「翻哪些位置」做成**数据**而不是写死在循环里，有两个好处：
 *   1. 测试能直接构造策略验证判定，不必通过修改源码来试；
 *   2. 集成方（preload.c）能按需要放宽 —— 例如某些工具确实把路径
 *      放在固定位置，可以登记成 path_option。
 *
 * 默认值刻意保守（只翻 argv[0]）：宁可少翻（那个路径稍后总会被
 * open/stat 钩子翻到），不可多翻（语义被改坏且无迹可循）。
 */
typedef struct {
    int translate_argv0;            /* 默认 1 */
    int translate_other_args;       /* 默认 0 —— 保守 */
    /*
     * 「取路径的选项」白名单：argv 里出现这些**精确**字面量时，
     * 紧随其后的那一个参数按路径处理。
     * 例如 {"-o", "--output", "-f", NULL}。
     *
     * 为什么用白名单而不是启发式：启发式（比如「像路径就翻」）
     * 会在 `sed 's/a/b/'`、`grep pattern` 上误判，而误判是静默的。
     */
    const char *const *path_options;
    size_t path_options_n;
} px_argpolicy;

/* 默认策略：translate_argv0=1, translate_other_args=0, 无选项白名单 */
extern const px_argpolicy PX_ARGPOLICY_DEFAULT;

/*
 * 判定单个 argv 条目。
 *
 * is_argv0        -- 是否为 argv[0]
 * rootfs          -- 当前 rootfs 前缀（可为 NULL，表示不做幂等判定）
 *
 * 幂等判定放在纯逻辑层而不是翻译函数里，是因为它是**判定**而非**动作**：
 * 钩子层据此决定「是否需要新建 argv 数组」，少一次分配就少一条失败路径。
 */
px_arg_verdict px_classify_arg(const char *arg, int is_argv0, const char *rootfs);

/* 带策略的完整版本。is_argv0 与 pol 共同决定这个位置是否该翻。 */
px_arg_verdict px_classify_arg_ex(const char *arg, int is_argv0,
                                  const char *rootfs, const px_argpolicy *pol);

/*
 * 判定某个 argv 元素是否应当把**下一个**元素当路径（即它是白名单里的
 * 「取路径选项」）。供计划层使用，也便于测试。
 * 支持 `--opt=value` 内联形式：此时返回 0（值已在同一个元素里，
 * 由调用方另行处理 —— 本实现不处理内联形式，理由见 REPORT）。
 */
int px_arg_is_path_option(const char *arg, const px_argpolicy *pol);

/*
 * 路径翻译函数注入。返回值约定与 preload.c 的 translate_path 完全一致：
 *   > 0  已翻译，结果写进 out（调用方必须使用 out）
 *   == 0 无需翻译，调用方沿用原指针
 *   < 0  失败（errno 语义），调用方应放弃并回落原状
 *
 * 约定一致是刻意的：钩子层直接把 preload.c 的 translate_path 包一层传进来，
 * 不引入第二套语义。
 */
typedef int (*px_xlate_fn)(void *ud, const char *path, char *out, size_t outsz);

/* 一次翻译改写。 */
typedef struct {
    size_t index;                    /* argv 下标 */
    char   text[PX_PATH_MAX];        /* 翻译结果 */
} px_arg_fix;

/*
 * argv 翻译计划。
 *
 * 之所以先出「计划」再「应用」，是为了让纯逻辑可测：测试可以只检查计划
 * （改写了哪几条、有没有多翻），而不必真的去 spawn 一个进程。
 */
/*
 * 一次计划里最多记多少条改写。
 *
 * ★ 这个值曾经是 PX_ARGV_MAX（4096），并**内嵌**进 px_argv_plan ——
 *   于是 `px_argv_plan` 结构体约 16.8 MB，任何局部变量都会立刻爆栈。
 *   实测症状是 E 组用例跑完后进程直接 SIGSEGV（栈溢出），
 *   而崩溃点与被改动的代码相距甚远，极难定位。
 *
 * 现在改成**懒分配的堆数组**，上限收到 1024：
 *   - 常见的 exec 只改写 1 条（argv[0]），此时完全不分配；
 *   - 1024 条 × 4 KiB ≈ 4 MiB，只在真有这么多绝对路径参数时才发生
 *     （内核 ARG_MAX 通常 2 MiB，实际到不了）；
 *   - 消除内嵌大数组，就消除了「与调用栈深度相关的偶发崩溃」这一整类问题。
 */
#define PX_PLAN_MAX 1024

/*
 * argv 翻译计划。
 *
 * 之所以先出「计划」再「应用」，是为了让纯逻辑可测：测试可以只检查计划
 * （改写了哪几条、有没有多翻），而不必真的去 spawn 一个进程。
 *
 * `fixes` 为 NULL 表示「没有任何改写」，此时应用阶段走零分配快路径。
 */
typedef struct {
    /*
     * ★ magic 不是装饰，是必需的 ★
     *
     * px_plan_reset 会**保留** fixes 缓冲以便复用（exec 是热路径），
     * 这就要求调用方传入一个「已初始化」的结构体。但本头文件的 API
     * 允许调用方写 `px_argv_plan plan;`（未初始化）后直接调
     * px_plan_argv —— 那样 reset 会读到栈上的垃圾 `cap`/`fixes`，
     * 于是 memcpy 进一个野指针。在 LD_PRELOAD 里这就是整个容器 SIGSEGV。
     *
     * magic 让「未初始化」变成可检测的：magic 不匹配就当场清零，
     * 与 `memset(plan, 0, sizeof(*plan))` 等价。用 0 之外的值是为了
     * 让「恰好全零的栈」也能被正确识别为未初始化（全零恰好也安全，
     * 但显式区分更清楚）。
     */
    unsigned long magic;
#define PX_PLAN_MAGIC 0xB8C0FFEE5A5A5A5Aul
    px_arg_fix *fixes;   /* 懒分配；NULL = 无改写 */
    size_t      n;
    size_t      cap;
    int         oom;     /* 计划过程中分配失败 */
    int         error;   /* 翻译函数返回负值 */
    int         err_at;  /* 出错的下标，-1 表示无 */
    /* 生成 fixes 时用的分配器（vfork 路径传 bump，常规路径为 NULL）。 */
    const px_alloc *alloc_of_plan;
    /* 翻译策略；NULL 表示用 PX_ARGPOLICY_DEFAULT。 */
    const px_argpolicy *policy;
} px_argv_plan;

/* 静态初始化器：需要把 plan 放在静态存储或结构体里时用它。 */
#define PX_PLAN_INIT { PX_PLAN_MAGIC, NULL, 0, 0, 0, 0, -1, NULL, NULL }

/* 复位（不释放 fixes，保留容量以便复用）。 */
void px_plan_reset(px_argv_plan *plan);

/* 释放内部缓冲。NULL 安全、幂等。 */
void px_plan_dispose(px_argv_plan *plan);

/*
 * 计算翻译计划。argv 必须是以 NULL 结尾的数组（NULL 允许，等价于空）。
 * 不修改 argv。**只在真的需要改写时才分配**（懒分配 fixes 数组）。
 * 返回 PX_OK / PX_ENOMEM / PX_EFULL（超出 PX_PLAN_MAX）。
 */
int px_plan_argv(char *const argv[], const char *rootfs,
                 px_xlate_fn xlate, void *ud, px_argv_plan *plan);

/*
 * 与 px_plan_argv 相同，但可指定分配器（NULL 用 libc）。
 *
 * 单独开一个入口而不是改签名，是为了让**最常见的那条路径**保持
 * 零参数膨胀。vfork 路径需要 bump 分配器时才用这个。
 */
int px_plan_argv_ex(char *const argv[], const char *rootfs,
                    px_xlate_fn xlate, void *ud, px_argv_plan *plan,
                    const px_alloc *alloc);

/*
 * 设置翻译策略（在 px_plan_argv 之前调用生效）。
 *
 * 单独一个 setter 而不是把 pol 塞进 px_plan_argv 的参数表：
 * 绝大多数调用方要默认策略，为它们多加一个参数是纯噪音，
 * 而参数表越长，把两个相邻指针传反的概率越高。
 * pol == NULL 恢复默认。
 */
void px_plan_set_policy(px_argv_plan *plan, const px_argpolicy *pol);

/*
 * 把计划应用到 argv，产出新的指针数组。
 *
 * **关键语义：argv 数组与未改写的字符串原地复用，不做深拷贝。**
 * 理由是 exec 之后内存不再回收，深拷贝只会在失败路径上制造泄漏；而
 * 未被改写的指针本来就指向调用方的内存，在 execve 返回前一直有效。
 *
 * *out_vec 为输出指针数组（长度 need_n + 1），need_n 由本函数填。
 * 计划为空（n == 0）时不需要任何缓冲，直接沿用原 argv，返回 PX_OK 且
 * *out_vec = argv、*need_n = 0。调用方据此走「零分配快路径」。
 */
int px_apply_argv(char *const argv[], const px_argv_plan *plan,
                  char **out_vec, size_t out_cap, size_t *need_n);

/* 便捷封装：判断计划是否需要重建 argv。 */
int px_plan_needs_rebuild(const px_argv_plan *plan);

/* ------------------------------------------------------------------ */
/* 3b. guest PATH 搜索                                                 */
/* ------------------------------------------------------------------ */

/*
 * `posix_spawnp` / `execvp` / `execvpe` 的 PATH 搜索**必须搜 guest 的 PATH**。
 *
 * 直接转发给真实实现在这里会错两处：搜的是宿主 PATH，且搜到的是宿主路径。
 * 正确做法是我们自己按 guest PATH 逐个候选翻译后探测（X_OK），
 * 再把命中的**宿主绝对路径**交给 `posix_spawn`（而非 spawnp）。
 *
 * 用 count/get 两个函数而不是返回数组，是为了不引入分配 ——
 * 候选列表最大可能是 PATH 的段数，内嵌数组会很大。
 *
 * 语义（与 POSIX 对齐）：
 *   - file 含 '/' → 只有 1 个候选，就是 file 本身（调用方不应再做搜索）；
 *   - PATH 为 NULL/空 → 视为 "/bin:/usr/bin"（POSIX 的 confstr(_CS_PATH) 语义）；
 *   - PATH 里的空段等价于 "."；
 *   - 不做去重（不做是因为去重会改变探测顺序，而顺序是有语义的）。
 */
size_t px_search_count(const char *file, const char *path_env);

/*
 * 取第 i 个候选（0 基）。成功返回 PX_OK；i 越界返回 PX_ENOENT；
 * 拼接后超长返回 PX_ETOOLONG。out 里得到的是**尚未翻译**的候选路径。
 */
int px_search_get(const char *file, const char *path_env, size_t i,
                  char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* 3c. 无分配（bump）分配器                                            */
/* ------------------------------------------------------------------ */

/*
 * 为什么需要一个「不会 malloc 的分配器」
 * ------------------------------------
 * `vfork` 的子进程与父进程**共享地址空间**，POSIX 只允许在 exec 之前调用
 * 异步信号安全的函数。在里面 `malloc` 会改写父进程的堆管理结构 ——
 * 父进程被唤醒后堆就坏了（这类崩溃的现场离原因极远，是最难查的一类）。
 *
 * 但 vfork 子进程里的 `execve` 同样需要 envp 重建（否则钩子丢失），
 * 而重建要内存。解法是把 `px_env_build` 的分配器换成一个**预分配缓冲上的
 * 纯 bump 分配器**：不碰堆、不调用 libc，用完（exec 成功或失败）整个重置即可。
 *
 * 分配器注入的设计在这里第二次付了红利：同一份 envp 重建逻辑既能配 libc
 * 堆（常规路径）也能配 bump（vfork 路径），而两者的行为都能单测。
 */
typedef struct {
    char     *base;
    size_t    cap;
    size_t    used;
    size_t    peak;
    size_t    high_water;     /* 历史最大 used，用于评估缓冲该开多大 */
    unsigned long refusals;   /* 因空间不足被拒绝的次数 */
    unsigned long allocs;
    /*
     * ops 表**内嵌**在 px_bump 里，而不是用进程级静态存储。
     * 这是刻意的：静态 ops 需要一个「当前 bump 是谁」的全局指针，
     * 而 vfork 子进程与父进程共享地址空间 —— 任何额外全局态都是
     * 在共享内存上做手脚。内嵌后 px_bump_ops 天然可重入、可嵌套测试。
     */
    px_alloc  ops;
} px_bump;

/*
 * 绑定一块调用方提供的缓冲。
 *
 * base **不需要**预先对齐 —— 分配器内部按绝对地址做 16 字节对齐
 * （这一点曾经写错成「对齐 used 偏移」，于是 base 未对齐时所有返回
 * 地址都未对齐；普通构建下恰好测不出来，UBSan 才暴露）。
 */
void px_bump_init(px_bump *b, char *base, size_t cap);

/* 把 used 归零（不擦除内容，只回收）。 */
void px_bump_reset(px_bump *b);

/* 返回可传给 px_env_build 的 ops 表（指向 b->ops，随 b 存活）。 */
const px_alloc *px_bump_ops(px_bump *b);

/* ================================================================== */
/* 4. kill 越界判定（安全边界）                                        */
/* ================================================================== */

/*
 * 为什么这是安全边界而不是功能
 * ---------------------------
 * 我们没有 pid 命名空间，容器进程看到的 pid 就是宿主 pid。因此
 * `kill(1, SIGKILL)` 会去杀宿主的 init，`kill(-1, SIGKILL)` 会杀光当前
 * uid 能杀的一切 —— 包括 DSHA 自己和 Android 的 app 进程。这在没有
 * 白名单的实现里是**真实且一键可达**的越界。
 *
 * 判定刻意是「白名单」而不是「黑名单」：只有我们自己创建过、且尚未回收的
 * pid 才放行；其余一律 EPERM。黑名单（比如「排除 pid < 100」）必然漏。
 */
typedef enum {
    PROC_KILL_PASS     = 0,  /* 放行到真实 kill */
    PROC_KILL_DENY     = 1,  /* 拒绝（容器外进程），errno = EPERM */
    PROC_KILL_FAKE_OK  = 2   /* 假装成功（不调用真实 kill） */
} proc_kill_verdict;

typedef struct {
    /* 是否保护自己（kill(getpid(), ...)）。默认 1 —— 自signal 是常规操作。 */
    int protect_self;
    /* 是否允许给「本进程的父进程」发信号。默认 1：
     * shell 的作业控制、wait 的实现、以及 DSHA 的 WebProcSel 都依赖它。 */
    int allow_parent;
    /* kill(0, sig) / kill(-1, sig) 这类广播。默认 0（拒绝）。
     * 这是最危险的形态，没有理由放行。 */
    int allow_broadcast;
    /* 目标 pid <= 0（进程组）时：仅当 |pid| 是账本里的 pid 或 pgid 才放行。 */
    int allow_group;
} px_killpolicy;

/* 默认策略：protect_self=1, allow_parent=1, allow_broadcast=0, allow_group=1 */
extern const px_killpolicy PX_KILLPOLICY_DEFAULT;

/*
 * 判定。
 *
 * `sys` 用来取 self/parent/自身进程组；self_pid 缓存由调用方传入以避免
 * 每次判定都进内核（kill 是热路径）。
 *
 * l 为 NULL 或 disabled 时：一律 PASS（退化为无保护，与未启用本层一致）。
 */
proc_kill_verdict px_check_kill(const px_ledger *l, const px_killpolicy *pol,
                                const px_sysops *sys, pid_t self_pid,
                                pid_t target, int sig);

/*
 * 信号白名单：**永远**放行的信号。
 *
 * SIGCHLD 必须放行：进程管理协议（shell、Node 的 libuv、Python 的
 * subprocess）会给自己发 SIGCHLD；拦掉它会让所有子进程回收停摆。
 * 注意这只影响「自己给自己发」，不影响对外的白名单判定。
 */
int px_signal_always_allowed(int sig);

/* ================================================================== */
/* 5. atfork 三件套                                                    */
/* ================================================================== */

/*
 * 为什么需要 atfork（以及不加会怎样）
 * ---------------------------------
 * `fork` 之后子进程是**地址空间副本**：钩子库还在、账本内存还在，但
 * **所有锁的状态是错的**。
 *
 * 不加会发生的三件事，按严重度排：
 *
 *   1. **死锁**（最严重）。父进程里某线程正持有账本锁时另一个线程 fork，
 *      子进程只复制了「锁被持有」这一事实，而**持锁的那个线程并不存在于
 *      子进程中**（fork 只复制调用线程）。子进程第一次查账本就会永久
 *      阻塞 —— 表现为 `posix_spawn`/`system` 在子进程里挂住，且**没有任何
 *      报错**，只有 ps 里一个 D 状态的进程。本层用 px_forkguard 的
 *      prepare/parent/child 消除它，并有确定性测试复现（test_proc.c 的
 *      F 组用例：对照组在子进程里必然超时）。
 *
 *   2. **结构不一致**。账本用开放寻址 + 墓碑：插入/淘汰是「先写槽位、
 *      后改 count/ tombs」的多步操作。若在两步之间 fork，子进程会看到
 *      count 与实际 LIVE 槽位数不符，于是装载率判断失真 —— 触发本不该
 *      触发的淘汰，把 live 条目驱逐掉（进而把可 kill 的子进程变成不可 kill）。
 *
 *   3. **pid 缓存过期**。子进程的 pid 变了，任何缓存了 self pid 的地方
 *      （kill 判定的 self_pid 快速路径）都必须失效，否则子进程会把自己
 *      当成父进程，把父进程的信号判定为自己 → 自我保护失效。
 *
 * 协议（与 glibc 的 fork 实现一致）：
 *   prepare: 取锁 → 之后到 fork 返回之间，账本一定处于一致状态
 *   parent : 放锁
 *   child  : 放锁 + 重置 pid 相关缓存
 * 锁是**非递归**的：prepare 只能被 fork 的那一个线程调用一次。
 */

/* 锁原语注入。测试可以注入一个「可观测」的实现来断言调用顺序。 */
typedef struct {
    void (*lock)(void *ud);
    void (*unlock)(void *ud);
    void *ud;
} px_lockops;

typedef struct {
    const px_lockops *lockops;
    int        enabled;         /* 关掉后三个回调只计数不做锁（用于对照组） */
    int        locked;          /* 当前是否处于 prepare 之后、parent/child 之前 */
    pid_t      fork_pid;        /* prepare 时的 pid，用于 child 里检出自增 */
    unsigned long prepare_calls;
    unsigned long parent_calls;
    unsigned long child_calls;
    unsigned long child_resets;
    unsigned long inconsistent_detected;  /* child 里发现锁状态不自洽的次数 */
} px_forkguard;

void px_forkguard_init(px_forkguard *g, const px_lockops *ops, int enabled);
void px_forkguard_set_enabled(px_forkguard *g, int enabled);

/*
 * 三个回调。语义与 pthread_atfork 完全一致。
 *
 * `ledger` 可以为 NULL；child 回调会调用 px_child_reset(ledger) 重置账本里
 * 与 pid 绑定的缓存，并把「本次 fork 出来的子进程」记进账本。
 *
 * 注意：**子进程的 pid 只有父进程知道**（fork 返回值）。child 回调里拿到的
 * 是自己的 pid，可以据此自我登记；父进程则在 fork 返回后调用
 * px_forkguard_parent_register() 登记新 pid。
 */
void px_forkguard_prepare(px_forkguard *g, px_ledger *l);
void px_forkguard_parent(px_forkguard *g, px_ledger *l);
void px_forkguard_child(px_forkguard *g, px_ledger *l);

/*
 * 父进程在 fork 返回后登记新子进程。失败（账本满）返回 PX_EFULL，
 * 此时**必须**把 fork 出来的子进程杀掉 —— 一个不在账本里的子进程
 * 无法被 kill（我们自己的白名单会拒绝），会变成失控的孤儿。
 * 这个约束由 px_fork_should_abort 表达。
 */
int px_forkguard_parent_register(px_forkguard *g, px_ledger *l, pid_t child);

/* 登记失败时是否应当放弃这个子进程。 */
int px_fork_should_abort(int reg_rc);

/*
 * 只做「重置 pid 相关缓存」的部分，不碰锁。
 * 独立导出是为了让钩子层在 vfork/posix_spawn 的子进程分支里也能复用。
 */
void px_child_reset(px_ledger *l);

/* ================================================================== */
/* 6. 钩子层（纯逻辑测试不编译）                                       */
/* ================================================================== */

/*
 * ★ 这里必须是 `#if !PX_PURE_LOGIC`（取值判定），不能写成
 *   `#if !defined(PX_PURE_LOGIC)`（存在性判定）★
 *
 * 因为开关是取值式的：`-DPX_PURE_LOGIC=0` 表示「要钩子层」。
 * 用 defined() 判定时该宏**已被定义**，于是钩子层的全部声明被跳过，
 * 而 proc.c 里的 `#if !PX_PURE_LOGIC` 却会去编译实现 ——
 * 结果是整片 `unknown type name 'px_rtconfig'`。
 * 这解释了为什么「纯逻辑模式编译通过、钩子模式编译爆炸」。
 */
#if !PX_PURE_LOGIC

/* 环境重建的运行时配置（由钩子层从环境变量读出）。 */
typedef struct {
    char  preload[PX_PRELOAD_MAX];   /* 我们的运行时库路径 */
    char  rootfs[PX_PATH_MAX];
    char  l2s_dir[PX_PATH_MAX];
    int   have_preload;              /* 是否拿到了自己的路径 */
    int   have_rootfs;
    int   inject;                    /* 总开关 */
    int   verbose;
} px_rtconfig;

/* 读一次配置（幂等）。返回是否成功启用。 */
int px_runtime_init(void);

/* 当前配置只读视图；未初始化返回 NULL。 */
const px_rtconfig *px_runtime_config(void);

/* 进程级账本单例；未初始化返回 NULL。 */
px_ledger *px_runtime_ledger(void);

/*
 * 给定调用方的 envp，产出保证含 LD_PRELOAD / BXROOT_* 的新环境。
 *
 * 返回 0 成功（*out 有效，调用方负责 px_env_dispose）；
 * 返回 -1 表示不需要/无法重建（调用方沿用原 envp）。errno 已置。
 *
 * **envp == NULL 时用进程的 environ** —— 这是钩子层该做的兜底：
 * `execv`/`execvp` 家族根本不传 envp，语义就是用当前环境。
 */
int px_runtime_build_env(char *const envp[], px_envout *out);

/* 翻译一条路径（薄封装，直接走 preload.c 注入的翻译器）。 */
int px_runtime_translate(const char *path, char *out, size_t outsz);

/*
 * 供 preload.c 注入的翻译器。preload.c 在构造函数里调用一次即可。
 * 注入前所有翻译回落「原样返回」。
 */
void px_runtime_set_translator(px_xlate_fn fn, void *ud);

/*
 * 记账当前进程自身（构造函数里调用一次）。
 * 这样 kill(getpid()) 之类不会被自己的白名单误伤。
 */
void px_runtime_register_self(void);

/* 钩子层的诊断计数。 */
typedef struct {
    unsigned long spawn_calls;
    unsigned long spawn_env_injected;
    unsigned long spawn_path_translated;
    unsigned long fork_calls;
    unsigned long vfork_calls;
    unsigned long exec_calls;
    unsigned long exec_env_injected;
    unsigned long kill_pass;
    unsigned long kill_deny;
    unsigned long kill_fake_ok;
    unsigned long system_calls;
    unsigned long popen_calls;
} px_rt_stats;

const px_rt_stats *px_runtime_stats(void);
void px_runtime_reset_stats(void);

#endif /* !PX_PURE_LOGIC */

#ifdef __cplusplus
}
#endif

#endif /* PROC_H */
