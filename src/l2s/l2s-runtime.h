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
    /* PRoot 用 access(F_OK) 探测候选中间层是否已被占用，它**跟随**符号链接，
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
 */
int l2s_rt_rewrite_readlink(const char *path, const char *raw_target,
                            char *out, size_t outsz);

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

/* statx 版本。statx_nlink_bit 传 STATX_NLINK，避免本头文件依赖 <linux/stat.h>。 */
void l2s_rt_patch_statx(unsigned int *stx_nlink, unsigned int *stx_mask,
                        unsigned int statx_nlink_bit, const char *path);

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
