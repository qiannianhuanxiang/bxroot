/*
 * l2s-runtime.h -- link-to-symlink 硬链接模拟的「运行时层」
 *
 * 纯逻辑（命名、编解码、nlink 推导）在 agents/l2s/l2s.c 里，本文件负责把
 * 那些纯函数接到真实的文件系统操作上。
 *
 * 设计要点：本层**不直接调用任何系统调用**，所有 FS 操作都经过 l2s_rt_ops
 * 函数表注入。这样做的原因很实际：本容器无法端到端验证 LD_PRELOAD（外层
 * proot 会吞掉 LD_PRELOAD），只有可注入的纯逻辑才测得动。测试注入一个内存
 * 文件系统，生产注入真实的 lstat/symlink/rename/unlink。
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef L2S_RUNTIME_H
#define L2S_RUNTIME_H

#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "l2s.h"

/* ------------------------------------------------------------------ */
/* 返回值约定                                                          */
/* ------------------------------------------------------------------ */

/*
 * 本层所有操作函数返回：
 *   0                 成功（已完全接管，调用方不得再调真实函数）
 *   L2S_RT_PASSTHRU   本条路径与 l2s 无关，调用方应回落真实函数
 *   -errno            失败，调用方应把 errno 设为 -rc 后返回 -1
 *
 * 注意 L2S_RT_PASSTHRU 是**负数**，与 -errno 同域。调用方必须先判定是否
 * 等于 L2S_RT_PASSTHRU，再当作错误处理。
 */
#define L2S_RT_PASSTHRU (-4096)

/*
 * l2s_rt_rewrite_readlink() 的第三个返回值：被 readlink 的东西是**伪造
 * 链接**，客户看到的应当是一个**普通文件** —— 于是 readlink 必须失败并置
 * errno=EINVAL，与 st_mode 的 S_IFREG 自洽。
 *
 * 调用方必须显式处理它（`errno = EINVAL; return -1;`）。**不能**把它当
 * 普通负数错误吞掉，也不能继续返回内核给的目标字符串 —— 那正是缺陷本身。
 */
#define L2S_RT_READLINK_FAKE (-4095)

/* ------------------------------------------------------------------ */
/* 注入的操作表                                                        */
/* ------------------------------------------------------------------ */

/*
 * 每个函数的返回值语义与 libc 一致（0 / -1，失败时置 errno），
 * 由注入方负责。本层只做 errno -> -errno 的搬运。
 */
typedef struct {
    int     (*lstat)(const char *path, struct stat *st);
    int     (*symlink)(const char *target, const char *linkpath);
    int     (*rename)(const char *oldpath, const char *newpath);
    int     (*unlink)(const char *path);
    ssize_t (*readlink)(const char *path, char *buf, size_t bufsiz);
    /* 参考实现 用 access(F_OK) 探测候选中间层是否已被占用，它**跟随**符号链接，
     * 所以悬空的中间层算「空闲」。注入方必须复现这一点。 */
    int     (*access)(const char *path, int mode);

    /* `.cnt` 引用计数旁路的小文件读写。
     * read_small：成功返回 0，内容写进 buf（NUL 结尾），*out_len 为字节数；
     *             文件不存在返回 -ENOENT。
     * write_small：成功返回 0（覆盖写，不追加）。 */
    int     (*read_small)(const char *path, char *buf, size_t bufsz,
                          size_t *out_len);
    int     (*write_small)(const char *path, const char *buf, size_t len);
} l2s_rt_ops;

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

/*
 * 绑定操作表并选定配置。l2s_dir 为 NULL 时中间层生成在原文件旁边；
 * 非 NULL 时集中生成在该目录（DSHA 生产用 PROOT_L2S_DIR）。
 *
 * 返回 0；cfg 为 NULL 时用默认配置。可重复调用（用于测试之间复位）。
 */
int l2s_rt_init(const l2s_rt_ops *ops, const l2s_config *cfg);

/* 当前是否启用。未 init 或已 shutdown 时，所有操作回落透传。 */
int l2s_rt_enabled(void);

/*
 * 关闭模拟。所有操作此后一律透传。
 *
 * 存在的理由不是洁癖：fork 之后子进程继承 g_enabled，但派生出去的进程
 * 可能并不该模拟（例如 exec 了一个不该被接管的工具）；测试也需要一个
 * 办法回到「未初始化」状态，否则 g_enabled 一旦置位就再也测不到透传分支。
 */
void l2s_rt_shutdown(void);

/* ------------------------------------------------------------------ */
/* 被接管的操作                                                        */
/* ------------------------------------------------------------------ */

/*
 * link(oldpath, newpath) 的语义核心。
 *
 * 首次链接：把 oldpath 的**内容**搬到 final，建中间层 -> final 的符号链接，
 * 再把 oldpath 本身变成指向中间层的符号链接；最后把 newpath 建成指向
 * 同一个中间层的符号链接。于是两个客户路径都指向同一份数据。
 *
 * 后续链接（oldpath 已经是一个伪造链接）：把 final 尾部的链接数加一，
 * 重命名 final，重新指向中间层，再为 newpath 建一条符号链接。
 */
int l2s_rt_link(const char *oldpath, const char *newpath);

/* unlink(path) 的语义核心：递减链接数；归零时删掉中间层与数据文件。 */
int l2s_rt_unlink(const char *path);

/* rename(oldpath, newpath)：搬运客户路径的同时搬运中间层与数据文件，
 * 否则重命名后原来的客户路径会留下悬空链接。 */
int l2s_rt_rename(const char *oldpath, const char *newpath);

/* ------------------------------------------------------------------ */
/* readlink 反转译                                                     */
/* ------------------------------------------------------------------ */

/*
 * 内核把伪造链接解析成中间层路径（`.l2s.<name>0001`）返回给客户，客户
 * 看到这个词就等于看穿了模拟。本函数把内核返回的原始目标改写成客户本来
 * 应该看到的东西。
 *
 * 覆盖两种来源：
 *   1. 直接 readlink(伪造链接)        -- path 本身是中间层名
 *   2. readlink("/proc/self/fd/N")    -- 内核对 fd 的解析结果
 *
 * 返回 1 表示已改写 out，0 表示无需改写（调用方用原值），负数为错误。
 *
 * ★ 2026-09-16 语义变更（两条分支，别一刀切）★
 *
 * 客户路径**直接**查询伪造链接（内核返回中间层名）时返回
 * L2S_RT_READLINK_FAKE —— 调用方转 EINVAL。
 *
 * 旧行为是把中间层名「还原」成客户本来的名字再返回成功。实测证明那个
 * 返回值会让客户判定"它是符号链接"，与 lstat 报的 S_IFREG **自相矛盾**，
 * 后果是真实工具链损坏（`cp -a` 报 ELOOP、`tar` 按符号链接归档并把宿主
 * 绝对路径写进归档）。参考实现 对同一路径返回 EINVAL，两者自洽。
 *
 * ★ 但第 2 条来源（/proc/self/fd/N）必须继续返回还原名 ★
 *
 * 那里内核已经把 fd 解析**穿透**整条链，返回的是**数据文件**路径 ——
 * 不是"客户正对着一条伪造链接"，而是"客户拿 fd 反查这是哪个文件"，
 * 理应拿到它自己用的名字。实测（官方）：`readlink(a)` → EINVAL，
 * 而伪造链接的 `readlink(/proc/self/fd/N)` → 返回客户路径。两条都对。
 * 一刀切成 EINVAL 会误伤 fd 反查名字（node 的 uv_exepath 等都在用）。
 */
int l2s_rt_rewrite_readlink(const char *path, const char *raw_target,
                            char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* 路径解链                                                            */
/* ------------------------------------------------------------------ */

/*
 * 把一个**伪造链接的客户路径**解析成它背后的最终数据文件路径。
 *
 * 用途：open/openat 带 O_NOFOLLOW 时不能让内核走到那条符号链接上
 * （内核会回 ELOOP）。客户从 lstat 得知这是普通文件，于是 coreutils
 * 的 `cp -a` 会用 O_NOFOLLOW 打开它 —— 内核看到的是符号链接，直接
 * ELOOP，`cp -a` 失败。参考实现不会：它在系统调用入口就把路径
 * 换成了数据文件，内核根本见不到那条链接。
 *
 * 返回 1 = 已解析（out 里是宿主侧的数据文件路径）；
 *      0 = 该路径不是伪造链接，调用方应原样使用；
 *      -errno = 出错。
 *
 * ★ 判据只有这一处 ★
 * 内部复用与 l2s_rt_patch_stat 完全相同的 probe_fake_link/resolve_final，
 * 不新造第二套"怎么认伪造链接"的规则。
 */
int l2s_rt_resolve_fake_link(const char *path, char *out, size_t outsz);

/* ------------------------------------------------------------------ */
/* stat 补丁                                                           */
/* ------------------------------------------------------------------ */

/*
 * 伪造链接在磁盘上是符号链接，st_nlink 恒为 1，且 st_mode 带 S_IFLNK。
 * 客户视角下它应该是普通文件、链接数为链长。本函数按路径推导链长并改写
 * st_nlink；S_IFLNK 是否抹掉由 l2s_rt_set_hide_symlink() 控制（默认抹）。
 *
 * 路径与 l2s 无关时不做任何修改。
 */
void l2s_rt_patch_stat(struct stat *st, const char *path);

/*
 * statx 版本。statx_nlink_bit 传 STATX_NLINK，避免本头文件依赖 <linux/stat.h>。
 *
 * ⚠️ 本函数**只**改写 stx_nlink，不改 stx_mode —— 保留 4 参数签名是为了
 * 不破坏既有调用方。需要连 S_IFLNK 一起抹掉（node/libuv 的 lstatSync()
 * 走裸 syscall(291)，读的正是 stx_mode）请用下面的 _full 版本。
 */
void l2s_rt_patch_statx(unsigned int *stx_nlink, unsigned int *stx_mask,
                        unsigned int statx_nlink_bit, const char *path);

/*
 * statx 的完整补丁：同时改写 stx_nlink 与 stx_mode 的 S_IFMT 位。
 *
 * 存在的理由是一处**实测缺陷**：参考实现在裸 statx 路径上把伪造
 * 链接的 stx_mode 报成 S_IFREG（实测 mode=0100600 islnk=0），而只补
 * nlink 的版本会让 lstatSync().isSymbolicLink() 仍为 true —— 客户照样
 * 看穿模拟。
 *
 * stx_mode 传 NULL 时退化成与 l2s_rt_patch_statx 完全相同的行为。
 * 是否抹掉 S_IFLNK 由 l2s_rt_set_hide_symlink() 控制（默认抹）。
 */
/*
 * ★ stx_mode 是 uint16_t，不是 unsigned int ★
 *
 * `struct statx` 的字段宽度**不一样**：
 *     stx_mask   __u32
 *     stx_nlink  __u32
 *     stx_mode   __u16   ← 只有 2 字节（offset 28，其后 offset 30 是
 *                          __u16 __spare0[1]）
 *
 * 早前这里把 stx_mode 声明成 `unsigned int *`，于是
 *     *stx_mode = (*stx_mode & ~S_IFMT) | S_IFREG;
 * 是一次 **4 字节写**，会一并覆盖 stx_mode(28-29) + __spare0(30-31)。
 *
 * 当前不致命（覆盖的恰好是 spare 字段），但这是**未定义行为**：
 * 它依赖"后面正好是 spare"这个巧合，而不是 ABI 契约 —— 一旦将来
 * 内核在 30-31 放了别的东西，就会静默写坏客户的结构体。
 * 编译器也为此报了 -Wincompatible-pointer-types（那正是告警门禁抓到的）。
 *
 * 用 uint16_t 后是精确的 2 字节写，与 ABI 一致。
 */
void l2s_rt_patch_statx_full(unsigned int *stx_nlink, unsigned int *stx_mask,
                             uint16_t *stx_mode,
                             unsigned int statx_nlink_bit, const char *path);

/*
 * 传**整个 struct statx 缓冲**的版本。
 *
 * 【为什么需要它】
 *
 * 上面那个三指针版本的签名决定了它**只能改 nlink / mask / mode** ——
 * 它拿不到 `stx_size` / `stx_ino` / `stx_blocks`。
 *
 * 而实测表明这些字段**必须改**：`statx` 是 coreutils 9.x / rsync / pnpm
 * 的现代主路径（`stat` 命令与 node 都走它），只改 nlink/mode 的结果是
 * `tar` 把伪造链接按符号链接归档（并写入宿主绝对路径）、`cp -a` 报 ELOOP。
 *
 * 【为什么不在调用方回填】
 * 那会把"怎么找最终数据文件、链长多少"的判据复制到 preload.c 与
 * syscall_guard.c 两处 —— 本项目已经因为"同一判据两处实现"出过多次缺陷
 * （fstatat 漏接、patch_stat 无人调用、envp 兜底只写在注释里）。
 *
 * 【参数形态】
 * `sx` 指向客户的 `struct statx`（调用方直接传它拿到的指针）。
 * 本层按**偏移**访问字段（不包含 <linux/stat.h>，避免与 <sys/stat.h> 冲突）——
 * 偏移经 offsetof 实测：stx_mask=0 stx_nlink=16 stx_mode=28
 *                    stx_ino=32 stx_size=40 stx_blocks=48
 */
void l2s_rt_patch_statx_buf(void *sx, unsigned int statx_nlink_bit,
                            const char *path);

/* 默认 1（客户不该看出这是符号链接）。置 0 便于诊断。 */
void l2s_rt_set_hide_symlink(int on);

/* 测试/诊断：统计各操作被真实接管的次数。 */
typedef struct {
    unsigned long link_first;      /* 首次链接 */
    unsigned long link_more;       /* 后续链接（加链长） */
    unsigned long unlink_dec;      /* 递减但未归零 */
    unsigned long unlink_free;     /* 归零回收 */
    unsigned long rename_moved;    /* 连带搬运中间层 */
    unsigned long readlink_fixed;  /* 反转译命中 */
    unsigned long nlink_patched;   /* stat 链长改写命中 */
} l2s_rt_stats;

const l2s_rt_stats *l2s_rt_get_stats(void);
void l2s_rt_reset_stats(void);

#endif /* L2S_RUNTIME_H */
