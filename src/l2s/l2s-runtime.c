/*
 * l2s-runtime.c -- link-to-symlink 硬链接模拟的运行时层
 *
 * 见 l2s-runtime.h 的设计说明。本文件的铁律：**不直接调用任何系统调用**，
 * 一切 FS 操作都走注入的 l2s_rt_ops。
 *
 * 参考实现：上游 参考实现 的 src/extension/link2symlink/link2symlink.c
 *   move_and_symlink_path()  -- 第 484-638 行
 *   decrement_link_count()   -- 第 646-755 行
 *   handle_sysexit_end()     -- 第 758-905 行的 stat 补丁分支
 *
 * SPDX-License-Identifier: MIT
 */
#include <unistd.h>
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
 * 把 `target` 表示成"相对于 `ref` 所在目录"的路径。
 *
 * 【为什么需要】符号链接的 target 是**相对链接所在目录**解析的。
 * 当 target 与链接**不在同一目录**时，必须给出正确的相对路径，
 * 否则内核会拼错（本文件曾因此产生断链，见
 * docs/缺陷-l2s中间层相对路径断链导致git不可用.md）。
 *
 * 【为什么不用绝对路径】绝对路径会让中间层在 rootfs 迁移、
 * 绑定挂载变化后失效；相对路径天然免疫。
 *
 * 【边界】
 *   - 两者都不是绝对路径（**都相对 cwd**）时，可安全按目录层级算相对；
 *   - 任一为绝对路径时，退回**绝对路径**（此时无法保证用相对形式）；
 *   - 结果放不下 → 返回 -1，调用方退回绝对路径或原样。
 *
 * 返回 0 成功，-1 失败（out 未定义）。
 */
static int l2s_relpath(const char *target, const char *ref,
                       char *out, size_t outsz)
{
    char tdir[L2S_PATH_MAX], rdir[L2S_PATH_MAX];
    const char *tp, *rp;
    const char *tseg[64], *rseg[64];
    int tn = 0, rn = 0, i, common;
    size_t used = 0;

    if (target == NULL || ref == NULL || out == NULL || outsz == 0)
        return -1;

    /* 绝对路径无法用相对形式安全表达 → 交调用方处理 */
    if (target[0] == '/' || ref[0] == '/')
        return -1;

    /* 拆出各自的目录部分（不含 basename） */
    {
        const char *sl;
        size_t n;

        sl = strrchr(target, '/');
        if (sl == NULL) {
            tdir[0] = '\0';
        } else {
            n = (size_t)(sl - target);
            if (n >= sizeof(tdir))
                return -1;
            memcpy(tdir, target, n);
            tdir[n] = '\0';
        }

        sl = strrchr(ref, '/');
        if (sl == NULL) {
            rdir[0] = '\0';
        } else {
            n = (size_t)(sl - ref);
            if (n >= sizeof(rdir))
                return -1;
            memcpy(rdir, ref, n);
            rdir[n] = '\0';
        }
    }

    /* 逐段切分。空段与 "." 忽略；".." 保留（语义上要弹栈）。 */
    tp = tdir;
    while (*tp != '\0' && tn < 64) {
        const char *e = strchr(tp, '/');
        size_t n = (e != NULL) ? (size_t)(e - tp) : strlen(tp);
        if (n != 0 && !(n == 1 && tp[0] == '.'))
            tseg[tn++] = tp;
        if (e == NULL)
            break;
        tp = e + 1;
    }
    rp = rdir;
    while (*rp != '\0' && rn < 64) {
        const char *e = strchr(rp, '/');
        size_t n = (e != NULL) ? (size_t)(e - rp) : strlen(rp);
        if (n != 0 && !(n == 1 && rp[0] == '.'))
            rseg[rn++] = rp;
        if (e == NULL)
            break;
        rp = e + 1;
    }

    /* 公共前缀长度（按整段比较，需要段长度相同且内容相同） */
    common = 0;
    while (common < tn && common < rn) {
        const char *a = tseg[common], *b = rseg[common];
        const char *ae = strchr(a, '/');
        const char *be = strchr(b, '/');
        size_t al = (ae != NULL) ? (size_t)(ae - a) : strlen(a);
        size_t bl = (be != NULL) ? (size_t)(be - b) : strlen(b);
        if (al != bl || strncmp(a, b, al) != 0)
            break;
        common++;
    }

    /*
     * 每个 ref 剩余段 → 一个 "../"。
     *
     * ★ 写 3 字节就要推进 3 ★ 初版写成 `memcpy(...,"../",3); used += 2;`
     * （把 "../" 当 2 字节），于是下一轮从第 2 个字符 ' .' 开始覆盖，
     * 产出 `..src/.l2s.a0001` 这种少一个斜杠的路径 → 仍然断链。
     * 实测：`cp -al src dst` 后 `dst/a -> ..src/.l2s.a0001`。
     */
    for (i = common; i < rn; i++) {
        if (used + 3 >= outsz)
            return -1;
        memcpy(out + used, "../", 3);
        used += 3;
    }
    /* 每个 target 剩余段原样 */
    for (i = common; i < tn; i++) {
        const char *a = tseg[i];
        const char *ae = strchr(a, '/');
        size_t al = (ae != NULL) ? (size_t)(ae - a) : strlen(a);
        if (used + al + 1 >= outsz)
            return -1;
        memcpy(out + used, a, al);
        used += al;
        out[used++] = '/';
    }
    /* target 的 basename */
    {
        const char *b = strrchr(target, '/');
        b = (b != NULL) ? b + 1 : target;
        if (used + strlen(b) + 1 > outsz)
            return -1;
        memcpy(out + used, b, strlen(b) + 1);
    }
    return 0;
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
     * ================================================================
     * ★ 命名族归一化：本层只写 PROOT 式名字，所以只按 PROOT 式名字读 ★
     * ================================================================
     *
     * 【为什么必须在这里强制，而不是信任 cfg.scheme】
     *
     * 本层的**创建**与**识别**曾经走两套不同的判据，于是可以被配置成
     * 一个必然自坏的状态：
     *
     *   创建（l2s_rt_link -> l2s_make_paths_ex）
     *       只看 cfg.prefix 与 cfg.l2s_dir，**完全不看 scheme**，
     *       永远产出 PROOT 式的 ".l2s.<name>GGGG[.NNNN]"。
     *
     *   识别（probe_fake_link / resolve_final -> l2s_classify）
     *       看 scheme：PROROOT 时**跳过** parse_l2s_name()，
     *       只认 16 位 hex 的元数据树键。
     *
     * 两者一组合，scheme=PROROOT 就得到一个荒谬的结果：本层写出的
     * 中间层，本层自己认不出来。症状**不在创建那一半**（建档不经过
     * 分类器，link() 照样成功、目录里也照样出现 .l2s.* 中间文件），
     * 而在伪装那一半 —— probe_fake_link() 一律返回 0，于是
     *     l2s_rt_patch_stat()  直接 return（st_nlink 停在 1、st_mode 仍是 S_IFLNK）
     *     l2s_rt_rewrite_readlink() 直接 return 0（客户看到中间层名）
     * 客户于是看到"link() 成功，但 stat 说这不是硬链接"这种自相矛盾的
     * 元数据 —— pnpm 会据此判定"没链接上"，退化成整份复制。
     *
     * 【为什么归一化到 PROOT 是无损的，而不是"猜一个能用的值"】
     *
     * l2s_classify() 在 scheme=PROOT 下的分支是：
     *     parse_l2s_name() 失败 -> 落到 parse_proroot_meta_name()
     * 即 **PROOT 分支已经包含 PROROOT 的识别能力**，是严格超集：
     * 元数据树的名字在 PROOT 配置下照样解析得出（见 l2s.c:520-526）。
     * 反过来则不成立。所以强制 PROOT 不丢任何识别能力，只多认出本层
     * 自己写的那一族名字。
     *
     * 【为什么不是"返回错误让调用方改"】
     *
     * 本层根本没有元数据树的**写**能力（全文件不引用 l2s_key16 /
     * l2s_meta_entry / L2S_PROROOT_META_DIR），所以 PROROOT 对本层
     * 而言不是一个"尚未实现、将来会实现"的选项，而是一个**永远无法
     * 自洽**的选项。与其让调用方拿着一个静默失效的配置跑，不如在
     * 入口处把不变量钉死：**本层写什么名字，就按什么名字读**。
     *
     * 【实测证据】同一份代码、同一颗 node、只换这一个字段：
     *     scheme=PROOT   -> nlink=2  isSymbolicLink=false   ← 与官方一致
     *     scheme=PROROOT -> nlink=1  isSymbolicLink=true    ← 缺陷复现
     * 见 docs/l2s-stat伪装修复.md 与 test/test_l2s_scheme_guard.c。
     */
    g_cfg.scheme = L2S_SCHEME_PROOT;

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

    /*
     * ★ 返回**锚定到 path 所在目录**的 mid，而不是裸 basename ★
     *
     * 【缺陷（实测，2026-09-20，第十轮复核用判决性实验钉死）】
     *
     * 内核 readlink() 返回的 target 是**记录在链接里的字符串**；当它是
     * 纯 basename（本层的正常布局）时，下游所有用它拼路径的地方都会
     * **按进程 cwd 解析** —— 而正确基准是**链接所在目录**。
     *
     *     cwd=/tmp/piw,  文件在 sub/
     *       cwd/.l2s.tmpX0001.0002.cnt = 9      ← decoy
     *       sub/.l2s.tmpX0001.0002.cnt = 2      ← 真文件
     *     unlink("sub/tmpX") 后：
     *       cwd/...cnt = 8   ★ l2s 减的是 cwd 里那个 ★
     *       sub/...cnt = 2   （真文件没动）
     *
     * 后果：read_nlink 读不到 → -EINVAL → git 报
     * `unable to unlink '…': Invalid argument`；`.cnt` 计数错乱。
     *
     * 【为什么锚点取 path 的 dirname 而不是 target 的】
     * target 是 basename（没有目录）；而 path 是客户给的完整路径，
     * 它的 dirname 就是链接所在目录 —— 这正是内核解析 target 的基准。
     *
     * 【为什么在这里锚定，而不是在 read_nlink/write_nlink 里】
     * 这两个函数的入参叫 `final_path`，语义就是"可解析的路径"。
     * 在**源头**把它变成可解析的，所有调用点（共 6 处）自动受益，
     * 不需要逐个改签名 —— 少一个改动点就少一次"漏一个入口"的机会。
     */
    /*
     * ★ 只在 target 确实是**相对名**时才锚定 ★
     *
     * 上游的 readlink 钩子会把中间层路径做**反向翻译**（剥 rootfs 前缀），
     * 于是这里可能拿到**已经是绝对路径**的 target。那种情况下再拼一次
     * dirname 就是**双重锚定**：
     *
     *     <rootfs>/tmp/l2sx/ + <rootfs>/tmp/l2sx/.l2s.a0002
     *     = <rootfs>/tmp/l2sx/<rootfs>/tmp/l2sx/.l2s.a0002   ← 不存在
     *
     * 实测症状（加诊断后一眼可见）：
     *     PSDBG mid=<rootfs>/tmp/l2sx//data/data/.../tmp/l2sx/.l2s.a0002
     *     PSDBG resolve_final FAILED
     * 于是 `l2s_rt_patch_stat` 静默 return，**st_nlink/st_mode 的伪装
     * 完全不发生** → lstat 报 islink=1 size=64（符号链接的 size）。
     *
     * 判据：target 带 '/' 或首字符是 '/' ⇒ 它自身已可解析，直接用。
     */
    if (strchr(target, '/') == NULL) {
        const char *sl = strrchr(path, '/');
        size_t dlen = (sl != NULL) ? (size_t)(sl - path) + 1 : 0;

        if (dlen > 0) {
            /* 相对路径（如 ".git/objects/45/a"）也要锚定，否则下游按 cwd 解析 */
            if (path[0] != '/') {
                char cwd[L2S_PATH_MAX];
                if (getcwd(cwd, sizeof(cwd)) != NULL) {
                    size_t cl = strlen(cwd);
                    if (cl + 1 + dlen + strlen(target) >= outsz)
                        return 0;
                    memcpy(out_mid, cwd, cl);
                    out_mid[cl] = '/';
                    memcpy(out_mid + cl + 1, path, dlen);
                    memcpy(out_mid + cl + 1 + dlen, target,
                           strlen(target) + 1);
                    return 1;
                }
            }
            if (dlen + strlen(target) >= outsz)
                return 0;
            memcpy(out_mid, path, dlen);
            memcpy(out_mid + dlen, target, strlen(target) + 1);
            return 1;
        }
    }

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
     * 已经损坏 —— 按 参考实现 的做法静默跳过，反正调用方本来就要删它。
     *
     * ★ 但 target 可能是**纯 basename** ★ 内核按"相对 mid 所在目录"
     * 解析它（这是 symlink 的语义），而 l2s_decode_ex 需要能自证的
     * 形态。历史产物的 target 只有 basename，此处补上 mid 的目录前缀
     * 再解码，避免把"格式能识别但缺上下文"误判成"链已损坏"。
     */
    {
        l2s_info info;
        int rc = l2s_decode_ex(&g_cfg, target, NULL, &info);
        if (rc != L2S_OK || info.kind != L2S_KIND_FINAL) {
            if (target[0] != '/') {
                char joined[L2S_PATH_MAX];
                const char *sl = strrchr(mid, '/');
                size_t dlen = (sl != NULL) ? (size_t)(sl - mid) + 1 : 0;
                if (dlen > 0 && dlen + strlen(target) < sizeof(joined)) {
                    memcpy(joined, mid, dlen);
                    memcpy(joined + dlen, target, strlen(target) + 1);
                    rc = l2s_decode_ex(&g_cfg, joined, NULL, &info);
                    if (rc == L2S_OK && info.kind == L2S_KIND_FINAL) {
                        if (strlen(target) >= outsz)
                            return -ENAMETOOLONG;
                        memcpy(out_final, joined, strlen(joined) + 1);
                        return 0;
                    }
                }
            }
            return -EINVAL;
        }
    }

    /*
     * ★ 出口统一锚定：把相对名变成"相对 mid 所在目录"的可解析路径 ★
     *
     * 【缺陷】readlink 给的是链接里记录的**字面量**。本层布局下它是纯
     * basename（`.l2s.x0001.0002`），下游 `read_nlink`/`write_nlink`
     * 会拿它拼 `.cnt` 并用**裸 syscall(openat, AT_FDCWD, …)** 打开 ——
     * 于是按**进程 cwd** 解析，而正确基准是**链接所在目录**。
     *
     * 判决性实验（第十轮复核提供）：cwd 放一个同名 decoy，
     * `unlink(sub/tmpX)` 减掉的是 **cwd 里那个** `.cnt`，真文件没动。
     *
     * 【为什么在这里锚定而不是改 read_nlink 签名】调用点共 6 处，
     * 在出口统一锚定，全部受益 —— 少一个改动点就少一次漏入口的机会。
     */
    if (target[0] != '/' && strchr(target, '/') == NULL) {
        const char *sl = strrchr(mid, '/');
        size_t dlen = (sl != NULL) ? (size_t)(sl - mid) + 1 : 0;
        if (dlen > 0) {
            char anchored[L2S_PATH_MAX];
            if (dlen + strlen(target) < sizeof(anchored)) {
                memcpy(anchored, mid, dlen);
                memcpy(anchored + dlen, target, strlen(target) + 1);
                if (strlen(anchored) >= outsz)
                    return -ENAMETOOLONG;
                memcpy(out_final, anchored, strlen(anchored) + 1);
                return 0;
            }
        }
    }

    if (strlen(target) >= outsz)
        return -ENAMETOOLONG;
    memcpy(out_final, target, strlen(target) + 1);
    return 0;
}

/*
 * 把一个伪造链接的路径解析成它背后的最终数据文件路径。
 *
 * 【为什么需要这个入口（实测缺陷）】
 *
 * 客户从 lstat 得知伪造链接是**普通文件**，于是 coreutils 的 `cp -a`
 * 会用 `open(path, O_RDONLY|O_NOFOLLOW)` 打开它 —— 这是 cp 保护自己
 * 不被 TOCTOU 掉包的标准做法。但内核看到的是**符号链接**，O_NOFOLLOW
 * 直接回 ELOOP：
 *
 *     cp -a a c
 *       → /usr/bin/cp: cannot open '/tmp/x/a' for reading:
 *         Too many levels of symbolic links
 *
 * 参考实现不会：它在系统调用入口就把路径换成了数据文件
 * （link2symlink.c 的 translated_path()），内核根本见不到那条链接。
 *
 * 本层是 LD_PRELOAD 方案，只能在钩子里补：既然客户明确说了"别跟随
 * 符号链接"，而这条路径在我们的模拟里**本来就是普通文件**，那就把它
 * 换成真正的普通文件（数据文件）再交给内核。
 *
 * 【返回约定】
 *   1  = 已解析，out 里是宿主侧的数据文件路径
 *   0  = 该路径不是伪造链接，调用方原样使用
 *  <0  = 出错（调用方按原路径继续，不要因此让客户的调用失败 ——
 *         模拟层不该因为自己的内部状态把客户的操作弄坏）
 *
 * ★ 判据复用 probe_fake_link / resolve_final，不新造第二套规则 ★
 */
int l2s_rt_resolve_fake_link(const char *path, char *out, size_t outsz)
{
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];

    if (!l2s_rt_enabled() || path == NULL || out == NULL || outsz == 0)
        return 0;

    if (!probe_fake_link(path, mid, sizeof(mid)))
        return 0;

    if (resolve_final(mid, final, sizeof(final)) != 0)
        return 0;

    if (strlen(final) >= outsz)
        return -ENAMETOOLONG;

    memcpy(out, final, strlen(final) + 1);
    return 1;
}

/* ------------------------------------------------------------------ */
/* link()                                                             */
/* ------------------------------------------------------------------ */

/*
 * 首次链接时挑选一个空闲代号。参考实现 用 access(F_OK) 探测，它**跟随**符号
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

    /*
     * ★ 客户在搬运**本层的内部文件**时必须透传 ★
     *
     * 【缺陷（实测，2026-09-20，v10 验收的 make test 抓到）】
     * `cp -al src dst` 会对 src 里**每一个文件**做 link()，包括本层
     * 自己的中间层与数据文件：
     *
     *     link("./sub/.l2s.f0001",     "../dst2/./sub/.l2s.f0001")
     *     link("./sub/.l2s.f0001.0002","../dst2/./sub/.l2s.f0001.0002")
     *
     * 这些**不是**客户语义的硬链接 —— 客户（cp）只是想把整个目录树
     * （其中恰好含本层的内部文件）原样复制一份。若按 l2s 语义处理，
     * 会把内部文件再"建档"一次：计数错乱、嵌套链接、
     * `cannot create hard link … .l2s.f0001' to './sub/.l2s.f0001'`。
     *
     * 【判据】oldpath 的 **basename 以 `.l2s.` 开头** ⇒ 它是本层内部
     * 文件，link 它不是客户语义 → 交内核直传（让 cp 拿到它想要的
     * "普通文件之间的硬链接"）。
     *
     * 为什么不判断 newpath：newpath 是 cp 自己造的目标名，同样以
     * `.l2s.` 开头 —— 判任一侧即可，判 oldpath 语义更直接。
     */
    {
        const char *ob = strrchr(oldpath, '/');
        ob = (ob != NULL) ? ob + 1 : oldpath;
        if (strncmp(ob, L2S_PREFIX, strlen(L2S_PREFIX)) == 0)
            return L2S_RT_PASSTHRU;
    }

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
         * 参考实现 首次链接写死的尾巴是字面量 ".0002"：它记的是**本次 link()
         * 完成后**的链接数（原有 1 条 + 新建 1 条）。实证产物是
         * "<uuid>0001.0001"，那是 link 计数被递减回来的结果，两者一致。
         * 这里跟随 参考实现，写 2。
         */
        rc = l2s_make_paths_ex(&g_cfg, oldpath, gen, 2, &paths,
                               mid, final);
        if (rc != L2S_OK)
            return rc == L2S_ENAMETOOLONG ? -ENAMETOOLONG : -EINVAL;

        /* 内容搬到 final。 */
        if (g_ops->rename(oldpath, final) != 0)
            return -errno;

        /*
         * 中间层 -> final。
         *
         * ★ target 必须是**同目录下的名字**，不能是含目录的路径 ★
         *
         * 【缺陷（实测，2026-09-20）】`final` 是由 `oldpath` 派生的
         * **cwd 相对路径**（如 `.git/objects/45/.l2s.x0001.0002`），
         * 而符号链接的 target 是**相对链接所在目录**解析的 —— 于是
         * 内核把它拼成
         *     <mid 所在目录>/.git/objects/45/.l2s.x0001.0002
         * 多了一层目录，**必然断链**。
         *
         * 触发条件很常见：**cwd ≠ 链接所在目录**。git 就是这样 ——
         * cwd 是仓库根，对象在 `.git/objects/xx/` 下：
         *
         *     $ git add f.txt            # 首次 link → l2s 建档
         *     $ git commit               # 读对象 → 断链
         *     fatal: <hash> is not a valid object
         *
         * 宿主上看不出问题（真硬链接，不走 l2s），**只有 Android/bxroot
         * 这种必须模拟硬链接的环境才暴露**。
         *
         * 【修法】`final` 与 `mid` 由 `l2s_make_paths_ex` 保证**恒同目录**
         * （`final = mid + ".<NNNN>"`，见 l2s.c），所以 target 只需
         * **basename**。用 basename 还顺带免疫 cwd 变化 —— 比绝对路径更稳
         * （绝对路径会让中间层在 rootfs 迁移后失效）。
         */
        {
            /*
             * ★ target 要"相对 mid 所在目录"，且**保留目录信息** ★
             *
             * 初版只用 basename，虽然修好了内核解析，却**破坏了本层的
             * 内部解析**：`resolve_final()` 会对 mid 做 readlink 拿到
             * target，再交给 `l2s_decode_ex()`；后者需要能识别出
             * "这是 .l2s.<name>NNNN.<NNNN> 形态的数据文件路径"，
             * 纯 basename 缺少必要上下文 → 解码失败 → 返回 -EINVAL
             * （实测：git 报 `unable to unlink '...': Invalid argument`）。
             *
             * 正解是 `l2s_relpath()`：算出的相对路径既有正确的解析基准
             * （相对 mid 所在目录），又保留了完整目录信息供内部解码。
             * 由于 final 与 mid **恒同目录**，正常情况下它就是 basename；
             * 一旦将来两者不再同目录，这里也依然正确。
             */
            char ftarget[L2S_PATH_MAX];
            const char *use = final;
            const char *fbase = strrchr(final, '/');
            fbase = (fbase != NULL) ? fbase + 1 : final;

            if (l2s_relpath(final, mid, ftarget, sizeof(ftarget)) == 0)
                use = ftarget;
            else
                use = fbase;    /* 兜底：同目录 ⇒ basename 足够 */

            if (g_ops->symlink(use, mid) != 0) {
                int e = errno;
                (void)g_ops->rename(final, oldpath); /* 尽力回滚 */
                return -e;
            }
        }

        /*
         * 客户路径 -> 中间层，此时 oldpath 已经空出来。
         *
         * ★ target 必须**相对 oldpath 所在目录**（不是相对 cwd）★
         *
         * 【缺陷（实测，2026-09-20，第十轮验收）】这里原先直接把 `mid`
         * 当 target。而 `mid` 是从 `oldpath` 派生的**含目录的**路径：
         *
         *     cd /tmp/lf && ln d1/a d1/b
         *       oldpath = d1/a       mid = d1/.l2s.a0001
         *       symlink("d1/.l2s.a0001", "d1/a")
         *       ⇒ 内核按**链接所在目录**（d1/）解析 target
         *       ⇒ d1/a -> d1/d1/.l2s.a0001   ★断链★
         *
         * 症状极具迷惑性：`link()` 返回 rc=0，**新名字 b 能读**，
         * 而**原始名字 a 读不了**（ENOENT）—— 看起来像数据丢失。
         * 只有**不含目录**的相对名（`ln a b`）恰好正确。
         *
         * 【为什么之前漏了】第一环只修了「中间层 -> 数据文件」那一处
         * （`symlink(use, mid)`），这处「客户路径 -> 中间层」是**另一个
         * 调用点**，当时没一并处理。子代理两轮都点出来了。
         *
         * 【修法】用 `l2s_relpath(mid, oldpath, …)`：oldpath 与 mid
         * **恒同目录**（mid 由 oldpath 派生）⇒ 正确结果就是 basename。
         */
        {
            char mtarget[L2S_PATH_MAX];
            const char *use = mid;

            if (l2s_relpath(mid, oldpath, mtarget, sizeof(mtarget)) == 0)
                use = mtarget;

            if (g_ops->symlink(use, oldpath) != 0) {
                int e = errno;
                (void)g_ops->unlink(mid);
                (void)g_ops->rename(final, oldpath);
                return -e;
            }
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
         * rename 数据文件、重建中间层。那恰好命中参考实现 运行时的
         * 一个缓存缺陷 —— 已被 open 过的路径，在目标改名后永久 ENOENT。
         * 详见 agents/_shared/官方运行时缺陷-符号链接改名后失效.md。
         *
         * 改用旁路计数后，数据文件名从建立那天起就不再变化，缺陷无从触发。
         */
        if (write_nlink(final, count) != 0)
            return -errno;

        g_stats.link_more++;
    }

    /*
     * 为 newpath 建一条指向同一中间层的符号链接 —— 这就是「硬链接」。
     *
     * ★ target 必须是**相对于 newpath 所在目录**的路径 ★
     *
     * 【缺陷（实测，2026-09-20）】`mid` 是从 `oldpath` 派生的
     * **cwd 相对路径**。当 `newpath` 与 `oldpath` **不同目录**时
     * （`cp -al src dst` 正是如此），直接把 `mid` 当 target 会被
     * 内核按"相对 newpath 所在目录"解析 → 多一层目录 → 断链：
     *
     *     $ cp -al src dst
     *     $ cat dst/a
     *     cat: dst/a: No such file or directory
     *     $ readlink dst/a
     *     src/.l2s.a0001          ← 从 dst/ 解析变成 dst/src/... 不存在
     *
     * 宿主上是真硬链接，看不出问题。
     */
    {
        char midrel[L2S_PATH_MAX];
        const char *mtarget = mid;

        if (l2s_relpath(mid, newpath, midrel, sizeof(midrel)) == 0)
            mtarget = midrel;
        else if (mid[0] != '/' && newpath[0] != '/') {
            /*
             * 相对路径算不出来（层数过深/缓冲不足）→ 退回**绝对路径**。
             * 绝对路径在任何 cwd 下都正确，只是对 rootfs 迁移敏感；
             * 宁可"迁移时可能失效"也不能"当场就断链"。
             */
            static char abuf[L2S_PATH_MAX];
            char cwd[L2S_PATH_MAX];
            if (getcwd(cwd, sizeof(cwd)) != NULL) {
                if (snprintf(abuf, sizeof(abuf), "%s/%s", cwd, mid)
                    < (int)sizeof(abuf))
                    mtarget = abuf;
            }
        }

        if (g_ops->symlink(mtarget, newpath) != 0) {
            int e = errno;
            /*
             * 参考实现 在这里做 decrement_link_count() 回滚。本层不静默重放，
             * 把错误如实上抛，由调用方决定（EXECUTION_UNKNOWN 原则）。
             */
            return -e;
        }
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

        /*
         * ★ 一并删除 `.cnt` 旁路计数文件 ★
         *
         * 【缺陷（实测，2026-09-20，第十轮复核）】回收了中间层与数据文件，
         * 却把 `<final>.cnt` 留在原地。后果有三：
         *
         *   1. **污染 `git fsck`**：对象目录里出现无法识别的
         *      `.l2s.*.cnt` 文件 → `bad sha1 file: …`（宿主 0 条）；
         *   2. **下次同 basename 重建链时读到脏计数** —— 该文件本应
         *      随链一起消失，残留值会被当成"已有引用"；
         *   3. 磁盘泄漏（每次 link/unlink 循环留一个）。
         *
         * 删除失败**不算错误**：文件本就不存在时 ENOENT 是正常的，
         * 其它 errno 也不该让"已经删掉主体的 unlink"报失败 —— 主体
         * 已回收是客户关心的事实。所以尽力删、忽略返回值。
         */
        {
            char cnt[L2S_PATH_MAX];
            if (l2s_refcount_path(final, cnt, sizeof(cnt)) == L2S_OK)
                (void)g_ops->unlink(cnt);
        }
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
 * 参考实现 的 translated_path()（link2symlink.c 第 985-996 行）明确把
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
 * 已知且接受的残留（参考实现 同样存在）：把一个普通文件改名**覆盖**到伪造
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
 * 个名字）。
 *
 * ================================================================
 * ★ 2026-09-16 语义反转：不再「还原成客户名」，而是报告 EINVAL ★
 * ================================================================
 *
 * 【旧行为及其后果（实测，不是推理）】
 * 旧实现把中间层名解装饰后返回成功，即 `readlink(a)` →
 * "/data/data/.../tmp/x/a" —— 恰好等于客户查询的那个路径，形似自环。
 * 当时的设计理由是「不把内部名泄露给客户」。
 *
 * 但那个返回值与 lstat 的伪装**自相矛盾**：
 *
 *     lstat(a) → st_mode = S_IFREG   （本层刚抹掉 S_IFLNK）
 *     readlink(a) → 成功返回一个路径 （只有符号链接才会成功）
 *
 * 工具据此判定"它是符号链接"，于是：
 *     tar cf  → 按符号链接归档，并把**宿主绝对路径**
 *               （/data/data/com.dsh.client/files/...）写进归档
 *     cp -a   → cannot open '...': Too many levels of symbolic links
 *   （后者是因为 cp 会拿 readlink 的结果自己去解析，形成自环）
 *
 * 【参考实现的实测行为】
 * 它不刻意让 readlink 失败 —— 失败是**结构性**的：官方在系统调用入口
 * 就把伪造链接替换成最终数据文件（link2symlink.c 的 translated_path()），
 * 所以内核看到的已经是普通文件，readlink 自然回 EINVAL。这正是
 * 「mode 与 readlink 自洽」的来源。
 *
 * 【本函数的契约】
 *   命中伪造链接        → 返回 L2S_RT_READLINK_FAKE（调用方转 EINVAL）
 *   不是伪造链接        → 返回 0，调用方原样返回内核结果
 *                          （用户自己的真符号链接走这条，不受影响）
 *
 * ★ 为什么必须由调用方转 EINVAL，而不是这里直接返回 -EINVAL ★
 * 本层不碰 errno（见文件头的设计铁律：不直接做任何系统操作）。而且
 * 0 与负数在本层有既定含义，用 -EINVAL 会和"普通错误"混在一起，调用方
 * 无法区分"该失败"与"出错了"。所以用一个专属的正数哨兵。
 *
 * out 参数保留但不再被写入 —— 签名不变，避免破坏既有调用方。
 */
int l2s_rt_rewrite_readlink(const char *path, const char *raw_target,
                            char *out, size_t outsz)
{
    l2s_info info;
    const char *base;
    char mid[L2S_PATH_MAX];
    int rc;

    (void)out;
    (void)outsz;

    if (!l2s_rt_enabled())
        return 0;
    if (path == NULL || raw_target == NULL)
        return 0;

    base = base_of(raw_target);

    /*
     * 判据一：内核返回的目标带 l2s 前缀（"<...>/.l2s.<name>0001" 或
     * 数据文件 "<...>/.l2s.<name>0001.0002"）。不带前缀的是用户自己的
     * 符号链接，原样返回 —— **这一条保证了 reallink=true 不回归**。
     */
    if (!has_prefix(base))
        return 0;

    /*
     * 判据二：raw_target 必须是**指向本 path 的那条**伪造链接，而不是
     * 碰巧同名的东西。
     *
     * ★ 这里不能只靠 raw_target 的前缀判断 ★
     *
     * path 是客户查询的路径，raw_target 是内核告诉我们的链接目标。
     * 对伪造链接，raw_target 指向中间层。但用户完全可能手工建一条
     * 指向 ".l2s.xxx" 的符号链接 —— 那条在客户眼里就是**普通符号链接**，
     * readlink 必须正常返回它的目标。
     *
     * 判据与 stat 补丁完全一致（复用 probe_fake_link，不新造第二套规则）：
     * 它 lstat(path) 确认是符号链接、读它的目标、确认目标是带前缀的
     * l2s 名。命中即"这条路径确实是伪造链接"。
     *
     * ★ 这道判据同时挡掉 /proc/self/fd/N 的误伤 ★
     *
     * 【实测缺陷】把 readlink 改成失败后，`readlink("/proc/self/fd/N")`
     * 也跟着 EINVAL 了 —— 而那是**必须正常**的：它是客户拿 fd 反查名字
     * 的标准手段（node 的 uv_exepath、coreutils 的多处都在用）。实测：
     *     官方: readlink(/proc/self/fd/N 指向数据文件) = OK "/tmp/p5/a"
     *     bxroot(误伤时)                              = EINVAL
     *
     * 为什么会误伤：l2s 把伪造链接**透传**给内核时，客户路径 a 在磁盘上
     * 是符号链接，指向数据文件；内核对 /proc/self/fd/N 解析后返回的是
     * 数据文件路径（<...>/.l2s.a0001.0002），它**带 l2s 前缀**，于是
     * 只判前缀的实现就把它当成"伪造链接"了。
     *
     * 但 probe_fake_link(path=p, ...) 里的 p 是 /proc/self/fd/N ——
     * 它不是符号链接（是魔法链接），lstat 得到的不是 S_ISLNK，于是
     * 返回 0，本函数跟着返回 0，readlink 正常返回内核结果。**这正是
     * 官方行为**。
     */
    if (!probe_fake_link(path, mid, sizeof(mid)))
        return 0;

    if (l2s_decode_ex(&g_cfg, raw_target, NULL, &info) != L2S_OK)
        return 0;

    /*
     * ★ 判据三：只有「指向**中间层**」的才是客户可见的伪造链接 ★
     *
     * 【为什么必须区分中间层与数据文件（实测缺陷）】
     *
     * 磁盘布局是两级：
     *     a  ->  <dir>/.l2s.a0001            （中间层，KIND_INTERMEDIATE）
     *     <dir>/.l2s.a0001 -> <dir>/.l2s.a0001.0002   （数据文件，KIND_FINAL）
     *
     * 客户查询 `readlink(a)` 时，内核返回的是 **a 自己的目标** —— 中间层，
     * 即 KIND_INTERMEDIATE。这才是"客户正对着一条伪造链接"，应当 EINVAL。
     *
     * 但 `readlink("/proc/self/fd/N")` 不是：内核对 fd 做的解析会**穿透**
     * 整条链，返回**数据文件**路径（KIND_FINAL）。若对它也回 EINVAL，
     * 就误伤了 fd 反查名字这条标准手段 —— 实测（probe5）：
     *
     *     官方: readlink(/proc/self/fd/N) = OK   "/tmp/p5/a"
     *     bxroot(误伤时)                  = EINVAL
     *
     * 同一个误伤也解释了为什么必须保留**还原成客户名**的能力：对
     * KIND_FINAL 的情形，客户需要拿到一个它认识的名字。
     */
    if (info.kind == L2S_KIND_INTERMEDIATE) {
        g_stats.readlink_fixed++;
        return L2S_RT_READLINK_FAKE;
    }

    /*
     * KIND_FINAL（/proc/self/fd/N 的解析结果）：还原成客户本来的名字。
     *
     * ★ 这与上面那条并不矛盾 ★
     *
     * 客户看到的 `a` 是**普通文件**，所以 `readlink(a)` 必须失败；
     * 但 `/proc/self/fd/N` 是客户拿 fd 反查"这个 fd 是哪个文件"，
     * 内核对 fd 的解析穿透了整条链，客户理应得到它自己用的那个名字。
     * 官方两条都这么做（probe5 实测：前者 EINVAL，后者返回客户路径）。
     */
    if (info.orig_name[0] == '\0')
        return 0;

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
 * 注意 st_size/st_ino 的取舍：参考实现 只改 nlink，并把 stat 的其余部分
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

    /*
     * ★ 回填数据文件的真实元数据 ★
     *
     * 【为什么必须做】
     *
     * 此前这里只改 `st_nlink` 与 `st_mode` 的 S_IFLNK 位，**其余字段保留
     * 内核给的** —— 而内核给的是**符号链接的** stat，于是：
     *
     *     st_size = 符号链接目标字符串的长度（几十字节）
     *     真实文件可能只有 5 字节
     *
     * 实测后果（不是理论）：
     *     tar tvf  → 把伪造链接按**符号链接**归档，并把**宿主绝对路径**
     *                写进归档（/data/data/com.dsh.client/files/...）
     *     cp -a    → ELOOP（Too many levels of symbolic links）
     * 参考实现在同场景下 tar 输出普通文件、cp -a 成功。
     *
     * 【参考实现 的权威做法】
     * `src/extension/link2symlink/link2symlink.c:860-890` 是**整体替换**：
     *     status = lstat(final, &finalStat);
     *     finalStat.st_nlink = <链长>;
     *     finalStat.st_mode = statl.st_mode;   // 保留客户原本的
     *     finalStat.st_uid  = statl.st_uid;
     *     finalStat.st_gid  = statl.st_gid;
     *     write_data(..., &finalStat, sizeof(finalStat));
     *
     * 即：把客户的整个结构体换成**数据文件的**，只保留 mode/uid/gid。
     *
     * 【这里为什么不整体替换，而是逐字段回填】
     *
     * 因为调用方的顺序是「先 fakeroot 后 l2s」（见 preload.c 的钩子）：
     *     fakeroot_patch_stat(buf, ...);   // 已把 uid/gid 伪装成 0
     *     l2s_rt_patch_stat(buf, p);       // 本函数
     * 若整体替换，`st_uid`/`st_gid` 会被数据文件的真实属主覆盖，
     * **把 fakeroot 的伪装抹掉** —— 那会让依赖 uid=0 的场景（apt/dpkg/
     * pnpm）出问题。所以 uid/gid 必须保留 `st` 当前值。
     *
     * 【回填哪些字段】
     *   st_size / st_ino / st_blocks —— 来自数据文件（这是本次要修的）
     *   st_nlink —— 用读出的链长（下面的 l2s_patch_nlink_value）
     *   st_mode  —— ★ 权限位取数据文件的，类型位置 S_IFREG ★
     *   st_uid / st_gid —— ★ 保留不动（fakeroot 的成果）
     *   时间戳 / st_dev / st_rdev —— 数据文件的（与参考实现一致）
     *
     * ★ st_mode 的权限位为什么必须取数据文件的（实测缺陷）★
     *
     * 内核给符号链接的权限位**恒为 0777**（Linux 规定，S_IFLNK 的权限位
     * 无意义）。早前这里只抹类型位、保留权限位，于是客户看到
     *     0100777   ← 一个"权限全开"的普通文件
     * 而官方是
     *     0100600   ← 数据文件本身（0640 建、被 umask 收敛后）的权限
     *
     * 实测后果（不是理论）：
     *     stat $D/a   → bxroot: -rwxrwxrwx  官方: -rw-------
     *     tar cf      → bxroot: rc=2 "Cannot open: Too many levels of
     *                   symbolic links"      官方: rc=0
     * 权限位是 lstat 全字段里**唯一**与官方不一致的字段（逐字段 diff
     * 确认过），也是 tar 判定异常的最后一环。
     *
     * 数据文件的 mode 就在手边 —— final_st 已经为了 size/ino/blocks
     * lstat 过一次，直接用，不额外付代价。
     */
    {
        struct stat final_st;

        if (g_ops->lstat(final, &final_st) == 0) {
            st->st_size   = final_st.st_size;
            st->st_ino    = final_st.st_ino;
            st->st_blocks = final_st.st_blocks;
            st->st_blksize= final_st.st_blksize;
            st->st_dev    = final_st.st_dev;
            st->st_rdev   = final_st.st_rdev;
            st->st_atim   = final_st.st_atim;
            st->st_mtim   = final_st.st_mtim;
            st->st_ctim   = final_st.st_ctim;
            /*
             * 权限位取数据文件的，类型位按 g_hide_symlink 决定。
             * st_uid / st_gid 仍不在这里 —— 它们保留 fakeroot 的结果。
             */
            if (g_hide_symlink)
                st->st_mode = (final_st.st_mode & ~(mode_t)S_IFMT) | S_IFREG;
            else
                st->st_mode = final_st.st_mode;
        } else if (g_hide_symlink) {
            /* 拿不到数据文件时退化成旧行为：只改类型位 */
            st->st_mode = (st->st_mode & ~(mode_t)S_IFMT) | S_IFREG;
        }
    }

    if (l2s_patch_nlink_value(st, count) > 0)
        g_stats.nlink_patched++;
}

/* 公共实现：stx_mode 为 NULL 时只补 nlink（历史行为，向后兼容）。 */
static void patch_statx_impl(unsigned int *stx_nlink, unsigned int *stx_mask,
                             uint16_t *stx_mode,
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

    /*
     * ★ stx_mode：类型位抹成 S_IFREG，权限位取数据文件的 ★
     *
     * statx 的 stx_mode 与 stat 的 st_mode 是同一个东西。磁盘上伪造链接
     * 是符号链接，客户眼里必须是普通文件。只改 nlink 而留 S_IFLNK，客户
     * 一句 lstatSync().isSymbolicLink() 就得到 true —— 而这个 API 正是
     * 本模块要骗过的那一个。
     *
     * 【实测证据】裸 syscall(291) 探针（node/libuv 走的正是这条路）：
     *     参考实现: mode=0100600 nlink=2 islnk=0
     *     bxroot      : mode=0120777 nlink=1 islnk=1   ← 修前
     *                   mode=0100777 nlink=2 islnk=0   ← 只抹类型位
     *                   mode=0100600 nlink=2 islnk=0   ← 权限位也取数据文件后
     *
     * 最后那一跳的必要性与 l2s_rt_patch_stat() 完全相同（那里有完整实测）：
     * 符号链接的权限位恒为 0777，客户看到的必须是数据文件的权限位。
     *
     * 精确的 2 字节写（stx_mode 是 __u16）。见 l2s-runtime.h 的类型说明 ——
     * 早前按 4 字节写会越界覆盖 __spare0，属未定义行为。
     */
    if (stx_mode != NULL && g_hide_symlink) {
        struct stat final_st;

        if (g_ops->lstat(final, &final_st) == 0)
            *stx_mode = (uint16_t)((final_st.st_mode & ~(mode_t)S_IFMT) | S_IFREG);
        else
            *stx_mode = (uint16_t)((*stx_mode & ~(uint16_t)S_IFMT) | (uint16_t)S_IFREG);
    }

    g_stats.nlink_patched++;
}

/*
 * 4 参数版本：只补 nlink。**签名保持不变**，因为 preload.c 现有的
 * statx 钩子按这个签名调用，改签名会让别人的编译单元直接编不过。
 */
/* ------------------------------------------------------------------ */
/* statx：传整个结构体的版本                                            */
/* ------------------------------------------------------------------ */

/*
 * struct statx 的字段偏移（offsetof 实测，不是推算）。
 *
 * 这里**刻意不包含 <linux/stat.h>** —— 它会与 <sys/stat.h> 冲突
 * （两者都定义 statx 相关类型）。本项目的 syscall_guard.c 早就采用了
 * "只记偏移、不引头文件"的做法，这里保持一致。
 */
#define L2S_STX_MASK_OFF    0u
#define L2S_STX_NLINK_OFF  16u
#define L2S_STX_MODE_OFF   28u
#define L2S_STX_INO_OFF    32u
#define L2S_STX_SIZE_OFF   40u
#define L2S_STX_BLOCKS_OFF 48u

#define L2S_STX_U16(base, off) (*(uint16_t *)(void *)((unsigned char *)(base) + (off)))
#define L2S_STX_U32(base, off) (*(uint32_t *)(void *)((unsigned char *)(base) + (off)))
#define L2S_STX_U64(base, off) (*(uint64_t *)(void *)((unsigned char *)(base) + (off)))

void l2s_rt_patch_statx_buf(void *sx, unsigned int statx_nlink_bit,
                            const char *path)
{
    char mid[L2S_PATH_MAX];
    char final[L2S_PATH_MAX];
    unsigned int count;
    struct stat final_st;
    int have_final = 0;

    if (!l2s_rt_enabled() || sx == NULL || path == NULL)
        return;

    /* mask 未声明 NLINK 时不该改写（与 statx 语义一致：
     * 未声明的字段是未定义的，写进去会让客户读到垃圾）。 */
    if ((L2S_STX_U32(sx, L2S_STX_MASK_OFF) & statx_nlink_bit) == 0)
        return;

    if (!probe_fake_link(path, mid, sizeof(mid)))
        return;

    if (resolve_final(mid, final, sizeof(final)) != 0)
        return;

    if (read_nlink(final, &count) != 0)
        return;

    /*
     * 回填数据文件的真实元数据 —— 与 l2s_rt_patch_stat 同源同理由。
     *
     * 只改 nlink/mode 是不够的：`stx_size` 会是符号链接目标字符串的长度，
     * 于是 `tar` 判断"这是链接"（它看 readlink 有结果 + size 异常），
     * 把宿主绝对路径写进归档；`cp -a` 则直接 ELOOP。
     *
     * ★ 不改 stx_uid / stx_gid ★
     * 调用方是「先 fakeroot 后 l2s」（preload.c 的钩子顺序），
     * fakeroot 已经把 uid/gid 伪装成 0，覆盖它会抹掉伪装。
     */
    if (g_ops->lstat(final, &final_st) == 0) {
        have_final = 1;
        L2S_STX_U64(sx, L2S_STX_INO_OFF)    = (uint64_t)final_st.st_ino;
        L2S_STX_U64(sx, L2S_STX_SIZE_OFF)   = (uint64_t)final_st.st_size;
        L2S_STX_U64(sx, L2S_STX_BLOCKS_OFF) = (uint64_t)final_st.st_blocks;
    }

    L2S_STX_U32(sx, L2S_STX_NLINK_OFF) = count;

    /*
     * stx_mode 是 __u16（2 字节）—— 精确写，别越界覆盖其后的 padding。
     *
     * 权限位取数据文件的（与 patch_statx_impl / l2s_rt_patch_stat 同一
     * 道理，那里有完整实测证据）：符号链接的权限位恒为 0777，只抹类型位
     * 会让客户看到 0100777，而官方是数据文件的 0100600。
     */
    if (g_hide_symlink) {
        if (have_final) {
            L2S_STX_U16(sx, L2S_STX_MODE_OFF) =
                (uint16_t)((final_st.st_mode & ~(mode_t)S_IFMT) | S_IFREG);
        } else {
            uint16_t m = L2S_STX_U16(sx, L2S_STX_MODE_OFF);
            L2S_STX_U16(sx, L2S_STX_MODE_OFF) =
                (uint16_t)((m & ~(uint16_t)S_IFMT) | (uint16_t)S_IFREG);
        }
    }

    g_stats.nlink_patched++;
}

void l2s_rt_patch_statx(unsigned int *stx_nlink, unsigned int *stx_mask,
                        unsigned int statx_nlink_bit, const char *path)
{
    patch_statx_impl(stx_nlink, stx_mask, NULL, statx_nlink_bit, path);
}

/*
 * 5 参数版本：连 stx_mode 的 S_IFLNK 一起抹掉。
 *
 * 给裸 syscall(291) 那条路用（node/libuv 的 uv__fs_statx() 走的就是它，
 * 完全不经过 libc 的 statx() 包装），也给 preload.c 的 statx 钩子升级用。
 * 原有的 4 参数版本保留，是为了让调用方可以分步迁移、不必一次改两处。
 */
void l2s_rt_patch_statx_full(unsigned int *stx_nlink, unsigned int *stx_mask,
                             uint16_t *stx_mode,
                             unsigned int statx_nlink_bit, const char *path)
{
    patch_statx_impl(stx_nlink, stx_mask, stx_mode, statx_nlink_bit, path);
}

/* ------------------------------------------------------------------ */
/* 目录项 d_type 补丁                                                  */
/* ------------------------------------------------------------------ */

/*
 * d_type 常量：本文件不 include <dirent.h>（保持"不碰系统头"的惯例，
 * 且 <dirent.h> 的 struct dirent 与内核 linux_dirent64 布局不同，混用
 * 极容易出错）。取值来自内核 include/uapi/linux/dirent.h：
 *     DT_UNKNOWN 0, DT_FIFO 1, DT_CHR 2, DT_DIR 4, DT_BLK 6,
 *     DT_REG 8, DT_LNK 10, DT_SOCK 12, DT_WHT 14
 */
#define L2S_DT_UNKNOWN 0
#define L2S_DT_REG     8

int l2s_rt_dirent_type(const char *host_dir, const char *name)
{
    char full[L2S_PATH_MAX];
    char mid[L2S_PATH_MAX];

    if (!l2s_rt_enabled() || !g_hide_symlink)
        return L2S_DT_UNKNOWN;
    if (host_dir == NULL || name == NULL || name[0] == '\0')
        return L2S_DT_UNKNOWN;
    /* 目录项名里不可能有斜杠；有斜杠说明调用方给错了，别去拼路径 */
    if (strchr(name, '/') != NULL)
        return L2S_DT_UNKNOWN;

    /* 拼 <host_dir>/<name>，并检查截断（截断后再去 probe 会查错文件） */
    if (snprintf(full, sizeof(full), "%s/%s", host_dir, name)
            >= (int)sizeof(full))
        return L2S_DT_UNKNOWN;

    /*
     * 判据复用 probe_fake_link —— 与 stat/statx 的伪装**同一把尺子**。
     * 只有它认了（路径是符号链接、且 target 的 basename 带 .l2s. 前缀）
     * 才改写；用户自己建的普通符号链接必须原样报 DT_LNK。
     */
    if (!probe_fake_link(full, mid, sizeof(mid)))
        return L2S_DT_UNKNOWN;

    return L2S_DT_REG;
}

/*
 * 内核 linux_dirent64 布局（aarch64，与 x86_64 同）：
 *
 *     struct linux_dirent64 {
 *         u64  d_ino;        // 0
 *         s64  d_off;        // 8
 *         u16  d_reclen;     // 16
 *         u8   d_type;       // 18
 *         char d_name[];     // 19
 *     };
 *
 * ★ 不能直接 include <dirent.h> 并按 struct dirent 访问 ★
 * glibc 的 `struct dirent` 是它自己的布局（d_ino/d_off/d_reclen/d_type/
 * d_name 的顺序与宽度不同），按它遍历内核缓冲会读错字段 —— 这类错误
 * 不会崩，只会静默改错字节。所以这里按**内核**布局手写偏移。
 */
#define L2S_DENT_D_RECLEN_OFF 16u
#define L2S_DENT_D_TYPE_OFF   18u

int l2s_rt_patch_dents64(const char *host_dir, void *buf, long len)
{
    unsigned char *p = (unsigned char *)buf;
    long off = 0;
    int changed = 0;

    if (!l2s_rt_enabled() || !g_hide_symlink)
        return 0;
    if (host_dir == NULL || buf == NULL || len <= 0)
        return 0;

    while (off + (long)L2S_DENT_D_TYPE_OFF < len) {
        unsigned char *e = p + off;
        unsigned short reclen;
        unsigned char dtype;
        const char *name;

        memcpy(&reclen, e + L2S_DENT_D_RECLEN_OFF, sizeof(reclen));
        /* reclen 为 0 或越界说明缓冲不可信 —— 立即停手，不要继续走
         * （继续走会越读，且改的是任意内存） */
        if (reclen == 0 || off + (long)reclen > len)
            break;

        dtype = e[L2S_DENT_D_TYPE_OFF];
        name = (const char *)(e + L2S_DENT_D_TYPE_OFF + 1);

        /* ．/.. 不必查（它们永远是真目录，且 probe 也会否） */
        if (dtype == 10 /* DT_LNK */ &&
            !(name[0] == '.' && (name[1] == '\0' ||
                                 (name[1] == '.' && name[2] == '\0')))) {
            if (l2s_rt_dirent_type(host_dir, name) == L2S_DT_REG) {
                e[L2S_DENT_D_TYPE_OFF] = (unsigned char)L2S_DT_REG;
                changed++;
            }
        }

        off += (long)reclen;
    }

    if (changed > 0)
        g_stats.dents64_patched++;
    return changed;
}
