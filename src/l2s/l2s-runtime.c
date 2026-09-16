/*
 * l2s-runtime.c -- link-to-symlink 硬链接模拟的运行时层
 *
 * 见 l2s-runtime.h 的设计说明。本文件的铁律：**不直接调用任何系统调用**，
 * 一切 FS 操作都走注入的 l2s_rt_ops。
 *
 * 参考实现：上游 PRoot 的 src/extension/link2symlink/link2symlink.c
 *   move_and_symlink_path()  -- 第 484-638 行
 *   decrement_link_count()   -- 第 646-755 行
 *   handle_sysexit_end()     -- 第 758-905 行的 stat 补丁分支
 *
 * SPDX-License-Identifier: MIT
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

#include "l2s-runtime.h"

/* ------------------------------------------------------------------ */
/* 状态                                                                */
/* ------------------------------------------------------------------ */

static const l2s_rt_ops *g_ops = NULL;
static l2s_config g_cfg;
static int g_enabled = 0;
static int g_hide_symlink = 1;
static l2s_rt_stats g_stats;
/*
 * 前缀必须能装下最长的一种：".proot.l2s." 是 11 个字符，加结尾 NUL 共 12。
 * 早先这里写成 8，会把 USERLAND 前缀截成 ".proot.l" —— 前缀比较就此全错，
 * 而且是静默的。缓冲区尺寸与 L2S_PREFIX_USERLAND 绑定，改前缀时不会漏。
 */
static char g_prefix[sizeof(L2S_PREFIX_USERLAND) > sizeof(L2S_PREFIX)
                     ? sizeof(L2S_PREFIX_USERLAND) : sizeof(L2S_PREFIX)];

/* ------------------------------------------------------------------ */
/* 小工具                                                              */
/* ------------------------------------------------------------------ */

/* 取 basename（不修改入参）。 */
static const char *base_of(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

/*
 * 判断名字是否带 l2s 前缀。
 *
 * 用前缀比较而不是 strstr：USERLAND 布局的名字是 ".proot.l2s.x"，它并不
 * 以 ".l2s." 开头（第 6 个字符起才是 "l2s."），用 strstr 会把两种布局
 * 混为一谈，编解码就会错位。
 */
static int has_prefix(const char *name)
{
    if (g_prefix[0] == '\0')
        return 0;
    return strncmp(name, g_prefix, strlen(g_prefix)) == 0;
}

/*
 * 从 `.cnt` 旁路读出链接数。
 *
 * 返回 0 成功；-ENOENT 表示旁路不存在（即从未建过链）。
 */
static int read_nlink(const char *final_path, unsigned int *out)
{
    char cnt[L2S_PATH_MAX];
    char buf[32];
    size_t len = 0;
    unsigned long v;
    int rc;

    rc = l2s_refcount_path(final_path, cnt, sizeof(cnt));
    if (rc != L2S_OK)
        return -ENAMETOOLONG;

    rc = g_ops->read_small(cnt, buf, sizeof(buf), &len);
    if (rc != 0)
        return rc;

    if (l2s_parse_count(buf, len, &v) != L2S_OK)
        return -EINVAL;
    if (v < 1 || v > L2S_NLINK_MAX)
        return -ERANGE;

    *out = (unsigned int)v;
    return 0;
}

/* 把链接数写进 `.cnt` 旁路。 */
static int write_nlink(const char *final_path, unsigned int n)
{
    char cnt[L2S_PATH_MAX];
    char buf[16];
    size_t len;
    int rc;

    rc = l2s_refcount_path(final_path, cnt, sizeof(cnt));
    if (rc != L2S_OK)
        return -ENAMETOOLONG;

    rc = l2s_format_count(n, buf, sizeof(buf));
    if (rc != L2S_OK)
        return -EINVAL;
    len = strlen(buf);

    return g_ops->write_small(cnt, buf, len);
}

/* ------------------------------------------------------------------ */
/* 生命周期                                                            */
/* ------------------------------------------------------------------ */

int l2s_rt_init(const l2s_rt_ops *ops, const l2s_config *cfg)
{
    if (ops == NULL)
        return -EINVAL;

    g_ops = ops;
    g_cfg = cfg != NULL ? *cfg : (l2s_config)L2S_CONFIG_DEFAULT;

    /*
     * 把前缀物化到本文件自己的缓冲区。
     *
     * 这里有一个曾经踩过的坑：只在前缀为 NULL 时才填充 g_prefix，会让
     * 调用方显式传入前缀时 g_prefix 保持空串，于是
     *     strncmp(name, "", 0) == 0
     * 恒真 —— 任何名字都被当成 l2s 产物，解析全错。所以无论前缀来自
     * 哪里，都必须落到 g_prefix。
     */
    snprintf(g_prefix, sizeof(g_prefix), "%s",
             g_cfg.prefix != NULL ? g_cfg.prefix : L2S_PREFIX);
    g_cfg.prefix = g_prefix;

    /*
     * 集中目录布局时，l2s_dir 也可能为 NULL（"中间层放在原文件旁边"），
     * 由 l2s 纯逻辑层处理，这里不需要额外动作。
     */
    g_enabled = 1;
    return 0;
}

int l2s_rt_enabled(void)
{
    return g_enabled && g_ops != NULL;
}

void l2s_rt_shutdown(void)
{
    g_enabled = 0;
    g_ops = NULL;
}

void l2s_rt_set_hide_symlink(int on)
{
    g_hide_symlink = on ? 1 : 0;
}

const l2s_rt_stats *l2s_rt_get_stats(void)
{
    return &g_stats;
}

void l2s_rt_reset_stats(void)
{
    memset(&g_stats, 0, sizeof(g_stats));
}

/* ------------------------------------------------------------------ */
/* 探测：路径是不是伪造链接                                            */
/* ------------------------------------------------------------------ */

/*
 * lstat(path)；不是符号链接或读不到就返回 0（与 l2s 无关）。
 * 是符号链接时读出它的目标，判断目标是不是指向 l2s 中间层。
 * 命中返回 1 并把中间层路径写进 out_mid。
 */
static int probe_fake_link(const char *path, char *out_mid, size_t outsz)
{
    struct stat st;
    char target[L2S_PATH_MAX];
    ssize_t n;

    if (g_ops->lstat(path, &st) != 0)
        return 0;
    if (!S_ISLNK(st.st_mode))
        return 0;

    n = g_ops->readlink(path, target, sizeof(target) - 1);
    if (n <= 0)
        return 0;
    target[n] = '\0';

    /*
     * 客户路径 -> 中间层。中间层的 basename 必须带前缀，否则这是用户
     * 自己建的普通符号链接，与我们无关。
     */
    if (!has_prefix(base_of(target)))
        return 0;

    /* 光看名字不够：还要确认它就是指向本路径的那条链，避免把用户手工
     * 创建的、恰好同名的符号链接当成伪造链接。 */
    if (strlen(target) >= outsz)
        return 0;
    memcpy(out_mid, target, strlen(target) + 1);
    return 1;
}

/*
 * 由中间层读出数据文件（final）路径。
 */
static int resolve_final(const char *mid, char *out_final, size_t outsz)
{
    char target[L2S_PATH_MAX];
    ssize_t n;

    n = g_ops->readlink(mid, target, sizeof(target) - 1);
    if (n <= 0)
        return -errno;
    target[n] = '\0';

    /*
     * 中间层必须指向一个数据文件（带 ".NNNN" 尾巴），指向别处说明链
     * 已经损坏 —— 按 PRoot 的做法静默跳过，反正调用方本来就要删它。
     */
    {
        l2s_info info;
        int rc = l2s_decode_ex(&g_cfg, target, NULL, &info);
        if (rc != L2S_OK || info.kind != L2S_KIND_FINAL)
            return -EINVAL;
    }

    if (strlen(target) >= outsz)
        return -ENAMETOOLONG;
    memcpy(out_final, target, strlen(target) + 1);
    return 0;
}

/* ------------------------------------------------------------------ */
/* link()                                                             */
/* ------------------------------------------------------------------ */

/*
 * 首次链接时挑选一个空闲代号。PRoot 用 access(F_OK) 探测，它**跟随**符号
 * 链接，因此悬空的中间层会被当成空闲槽位 —— 这个语义由注入方复现。
 *
 * l2s_exists_fn 的签名是 int (*)(const char *, void *)。
 */
static int exists_cb(const char *candidate, void *ctx)
{
    (void)ctx;
    return g_ops->access(candidate, F_OK) == 0;
}

int l2s_rt_link(const char *oldpath, const char *newpath)
{
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];
    l2s_paths paths;
    struct stat st;
    unsigned int gen, count;
    int rc, is_fake;

    if (!l2s_rt_enabled())
        return L2S_RT_PASSTHRU;
    if (oldpath == NULL || newpath == NULL)
        return -EINVAL;

    /* 目录不能硬链接。 */
    if (g_ops->lstat(oldpath, &st) != 0)
        return -errno;
    if (S_ISDIR(st.st_mode))
        return -EPERM;

    is_fake = probe_fake_link(oldpath, mid, sizeof(mid));

    if (!is_fake) {
        /* ---- 首次链接：建档 ---- */
        const char *base = base_of(oldpath);

        if (!S_ISLNK(st.st_mode) && base[0] == '\0')
            return -EINVAL;

        rc = l2s_pick_generation(&g_cfg, oldpath, exists_cb, NULL, &gen);
        if (rc != L2S_OK)
            return rc == L2S_ERANGE ? -ENOSPC : -EINVAL;

        /*
         * PRoot 首次链接写死的尾巴是字面量 ".0002"：它记的是**本次 link()
         * 完成后**的链接数（原有 1 条 + 新建 1 条）。实证产物是
         * "<uuid>0001.0001"，那是 link 计数被递减回来的结果，两者一致。
         * 这里跟随 PRoot，写 2。
         */
        rc = l2s_make_paths_ex(&g_cfg, oldpath, gen, 2, &paths,
                               mid, final);
        if (rc != L2S_OK)
            return rc == L2S_ENAMETOOLONG ? -ENAMETOOLONG : -EINVAL;

        /* 内容搬到 final。 */
        if (g_ops->rename(oldpath, final) != 0)
            return -errno;

        /* 中间层 -> final。 */
        if (g_ops->symlink(final, mid) != 0) {
            int e = errno;
            (void)g_ops->rename(final, oldpath); /* 尽力回滚 */
            return -e;
        }

        /* 客户路径 -> 中间层，此时 oldpath 已经空出来。 */
        if (g_ops->symlink(mid, oldpath) != 0) {
            int e = errno;
            (void)g_ops->unlink(mid);
            (void)g_ops->rename(final, oldpath);
            return -e;
        }

        /*
         * 落下旁路计数 = 2（原有 1 条 + 本次新建 1 条）。
         *
         * 这一步不能省：后续 link()/unlink()/stat 全靠读它。少了它，
         * 第二次 link() 会因读不到计数而失败，stat 也报不出链长。
         * 放在最后做，是因为前面任何一步失败都已经回滚、不该留下计数。
         */
        if (write_nlink(final, 2) != 0) {
            int e = errno;
            (void)g_ops->unlink(oldpath);
            (void)g_ops->unlink(mid);
            (void)g_ops->rename(final, oldpath);
            return -e;
        }

        g_stats.link_first++;
    } else {
        /* ---- 后续链接：只把旁路计数加一 ---- */
        rc = resolve_final(mid, final, sizeof(final));
        if (rc != 0)
            return rc;

        if (read_nlink(final, &count) != 0)
            return -EINVAL;
        count++;
        if (count > L2S_NLINK_MAX)
            return -EMLINK;

        /*
         * 关键：**不动数据文件的名字，也不动中间层**。
         *
         * 原设计把链接数编进文件名（.0002 -> .0003），每次加链长都要
         * rename 数据文件、重建中间层。那恰好命中官方 proroot 运行时的
         * 一个缓存缺陷 —— 已被 open 过的路径，在目标改名后永久 ENOENT。
         * 详见 agents/_shared/官方运行时缺陷-符号链接改名后失效.md。
         *
         * 改用旁路计数后，数据文件名从建立那天起就不再变化，缺陷无从触发。
         */
        if (write_nlink(final, count) != 0)
            return -errno;

        g_stats.link_more++;
    }

    /* 为 newpath 建一条指向同一中间层的符号链接 —— 这就是「硬链接」。 */
    if (g_ops->symlink(mid, newpath) != 0) {
        int e = errno;
        /*
         * PRoot 在这里做 decrement_link_count() 回滚。本层不静默重放，
         * 把错误如实上抛，由调用方决定（EXECUTION_UNKNOWN 原则）。
         */
        return -e;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* unlink()                                                           */
/* ------------------------------------------------------------------ */

int l2s_rt_unlink(const char *path)
{
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];
    unsigned int count;
    int rc;

    if (!l2s_rt_enabled())
        return L2S_RT_PASSTHRU;
    if (path == NULL)
        return -EINVAL;

    if (!probe_fake_link(path, mid, sizeof(mid)))
        return L2S_RT_PASSTHRU;

    rc = resolve_final(mid, final, sizeof(final));
    if (rc != 0) {
        /* 链已损坏 —— 反正是要删的，直接删客户路径。 */
        if (g_ops->unlink(path) != 0)
            return -errno;
        g_stats.unlink_free++;
        return 0;
    }

    if (read_nlink(final, &count) != 0)
        return -EINVAL;

    if (count > 1) {
        /* 还有人引用：只把旁路计数减一，数据文件名保持不动。 */
        count--;
        if (write_nlink(final, count) != 0)
            return -errno;
        g_stats.unlink_dec++;
    } else {
        /* 最后一条：中间层与数据文件一起回收。 */
        if (g_ops->unlink(mid) != 0)
            return -errno;
        if (g_ops->unlink(final) != 0)
            return -errno;
        g_stats.unlink_free++;
    }

    if (g_ops->unlink(path) != 0)
        return -errno;
    return 0;
}

/* ------------------------------------------------------------------ */
/* rename()                                                           */
/* ------------------------------------------------------------------ */

/*
 * 改名**故意透传**。
 *
 * 直觉上会想「把中间层与数据文件一起搬走」，但那是错的，而且偏离参考实现。
 * PRoot 的 translated_path()（link2symlink.c 第 985-996 行）明确把
 * rename/renameat/renameat2 排除在路径翻译之外：
 *
 *     if (sysnum == PR_rename || sysnum == PR_renameat || sysnum == PR_renameat2)
 *             return;
 *
 * 于是内核直接搬走那条**符号链接**。链依然解析：客户路径变了，中间层与
 * 数据文件原地不动，引用关系完好。中间层的名字里虽然还带着旧 basename，
 * 但那只是内部记账用的名字，客户看不见，也不影响解析。
 *
 * 我原先的实现会重建中间层，反而引入两个风险：中途失败留下悬空链接；
 * 以及 nlink 记账挂在中间层上，换名等于换账本。透传没有这些问题。
 *
 * 已知且接受的残留（PRoot 同样存在）：把一个普通文件改名**覆盖**到伪造
 * 链接上时，内核会用新文件替换掉那条符号链接，中间层与数据文件变成无人
 * 引用的孤儿，占用空间直到被清理。要修需要反向扫描整个元数据目录，代价
 * 远高于收益，且会让行为偏离参考实现，故不处理。
 */
int l2s_rt_rename(const char *oldpath, const char *newpath)
{
    (void)oldpath;
    (void)newpath;
    return L2S_RT_PASSTHRU;
}

/* ------------------------------------------------------------------ */
/* readlink 反转译                                                     */
/* ------------------------------------------------------------------ */

/*
 * 客户 readlink 一个伪造链接时，内核返回中间层路径（客户从没听说过这
 * 个名字）。两种改写：
 *
 *   1. raw_target 形如 "<dir>/.l2s.<name>0001"     -> 还原成客户视角
 *   2. raw_target 形如 "<dir>/.l2s.<name>0001.0002" -> 还原成客户视角
 *
 * 客户视角是什么？PRoot 的做法是让 readlink 返回**它所指向的数据文件**
 * 的客户化名字，也就是把中间的 l2s 装饰剥掉。对一个真实的硬链接，
 * readlink 本来应当 EINVAL —— 但模拟层不能返回 EINVAL，因为上层
 * （如 coreutils 的 cp -l 探测）会据此判断；PRoot 选择返回解装饰后的路径。
 */
int l2s_rt_rewrite_readlink(const char *path, const char *raw_target,
                            char *out, size_t outsz)
{
    l2s_info info;
    const char *base;
    int rc;

    if (!l2s_rt_enabled())
        return 0;
    if (path == NULL || raw_target == NULL || out == NULL || outsz == 0)
        return -EINVAL;

    base = base_of(raw_target);

    /*
     * 只处理带 l2s 前缀的目标。不带前缀的是用户自己的符号链接，
     * 原样返回。
     */
    if (!has_prefix(base))
        return 0;

    rc = l2s_decode_ex(&g_cfg, raw_target, NULL, &info);
    if (rc != L2S_OK)
        return 0;

    /*
     * 中间层与数据文件都还原成「原始 basename」。两者的区别只在于
     * 链接数，而链接数是模拟的内部记账，客户不该看见。
     */
    if (info.orig_name[0] == '\0')
        return 0;

    /*
     * 原始文件所在的目录：只有「中间层与原文件同目录」的布局才能还原出
     * 目录。集中目录布局下编码本身不记录原目录，此时退化成只返回
     * basename —— 与 PRoot 自己的信息量相同，不假装知道得更多。
     */
    if (info.dir_known && info.orig_dir[0] != '\0')
        rc = snprintf(out, outsz, "%s/%s", info.orig_dir, info.orig_name);
    else
        rc = snprintf(out, outsz, "%s", info.orig_name);

    if (rc < 0 || (size_t)rc >= outsz)
        return -ENAMETOOLONG;

    g_stats.readlink_fixed++;
    return 1;
}

/* ------------------------------------------------------------------ */
/* stat 补丁                                                           */
/* ------------------------------------------------------------------ */

/*
 * 让伪造链接看起来像真实硬链接：
 *   - st_nlink 改成链长（磁盘上是符号链接，内核只会给 1）
 *   - 抹掉 S_IFLNK（客户不该知道这是符号链接）
 *
 * 注意 st_size/st_ino 的取舍：PRoot 只改 nlink，并把 stat 的其余部分
 * 换成数据文件的（见 handle_sysexit_end 的 finalStat）。本层采取同样
 * 的最小改动，只动 nlink 与 mode 的 S_IFLNK 位，其余字段保持内核给的
 * 值 —— 因为本层拿不到 data 文件的 stat（那需要一次额外的 lstat，
 * 在 stat 热路径上代价太高）。
 */
void l2s_rt_patch_stat(struct stat *st, const char *path)
{
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];
    unsigned int count;

    if (!l2s_rt_enabled() || st == NULL || path == NULL)
        return;

    if (!probe_fake_link(path, mid, sizeof(mid)))
        return;

    if (resolve_final(mid, final, sizeof(final)) != 0)
        return;

    if (read_nlink(final, &count) != 0)
        return;

    if (l2s_patch_nlink_value(st, count) > 0) {
        if (g_hide_symlink)
            st->st_mode = (st->st_mode & ~(mode_t)S_IFMT) | S_IFREG;
        g_stats.nlink_patched++;
    }
}

void l2s_rt_patch_statx(unsigned int *stx_nlink, unsigned int *stx_mask,
                        unsigned int statx_nlink_bit, const char *path)
{
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];
    unsigned int count;

    if (!l2s_rt_enabled() || stx_nlink == NULL || stx_mask == NULL ||
        path == NULL)
        return;

    if ((*stx_mask & statx_nlink_bit) == 0)
        return;

    if (!probe_fake_link(path, mid, sizeof(mid)))
        return;

    if (resolve_final(mid, final, sizeof(final)) != 0)
        return;

    if (read_nlink(final, &count) != 0)
        return;

    *stx_nlink = count;
    g_stats.nlink_patched++;
}
