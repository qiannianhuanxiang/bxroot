/*
 * test_l2s_rt.c -- l2s 运行时层的测试
 *
 * 两类测试：
 *
 *   A. 真实文件系统端到端（主要证据）
 *      因为本层把 FS 操作全部经 l2s_rt_ops 注入，测试可以把它们接到**真实的**
 *      libc 调用上，于是能在真实 f2fs 目录里跑完整的 link/unlink/readlink 场景。
 *      这不是 LD_PRELOAD 模拟 —— 本层本来就不是 LD_PRELOAD，它只是一个库，
 *      所以这条路径在本容器里是完全可信的。这正是「注入式 ops」这个设计的回报。
 *
 *   B. 故障注入（错误路径）
 *      内存 FS 可以精确制造 ENOSPC/EPERM/ENOENT，验证错误传播与回滚。
 *
 * SPDX-License-Identifier: MIT
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "l2s-runtime.h"

/* ------------------------------------------------------------------ */
/* 断言框架                                                            */
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
        long _a = (long)(a), _b = (long)(b);                          \
        if (_a != _b) {                                               \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s=%ld, expected %s=%ld\n",\
                    __FILE__, __LINE__, #a, _a, #b, _b);              \
        }                                                             \
    } while (0)

#define CASE(name) do {                                               \
        g_cases++;                                                    \
        printf("- %s\n", name);                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/* A. 真实文件系统 ops                                                 */
/* ------------------------------------------------------------------ */

static int real_lstat(const char *p, struct stat *st) { return lstat(p, st); }
static int real_symlink(const char *t, const char *l) { return symlink(t, l); }
static int real_rename(const char *o, const char *n) { return rename(o, n); }
static int real_unlink(const char *p) { return unlink(p); }
static ssize_t real_readlink(const char *p, char *b, size_t s) { return readlink(p, b, s); }
static int real_access(const char *p, int m) { return access(p, m); }

static int real_read_small(const char *p, char *buf, size_t bufsz, size_t *out_len)
{
    int fd = open(p, O_RDONLY);
    ssize_t n;
    if (fd < 0)
        return -errno;
    n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -errno;
    buf[n] = '\0';
    *out_len = (size_t)n;
    return 0;
}

static int real_write_small(const char *p, const char *buf, size_t len)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ssize_t n;
    if (fd < 0)
        return -errno;
    n = write(fd, buf, len);
    close(fd);
    return n == (ssize_t)len ? 0 : -EIO;
}

static const l2s_rt_ops REAL_OPS = {
    real_lstat, real_symlink, real_rename, real_unlink,
    real_readlink, real_access,
    real_read_small, real_write_small
};

/* ------------------------------------------------------------------ */
/* 测试沙箱                                                            */
/* ------------------------------------------------------------------ */

static char g_root[PATH_MAX];

/* 递归删除，跳过符号链接（不能跟随，否则会删到链目标）。 */
static void rm_tree(const char *path)
{
    struct stat st;
    DIR *d;
    struct dirent *e;

    if (lstat(path, &st) != 0)
        return;
    if (!S_ISDIR(st.st_mode)) {
        unlink(path);
        return;
    }
    d = opendir(path);
    if (d != NULL) {
        while ((e = readdir(d)) != NULL) {
            char child[PATH_MAX];
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            snprintf(child, sizeof(child), "%s/%s", path, e->d_name);
            rm_tree(child);
        }
        closedir(d);
    }
    rmdir(path);
}

static void sandbox_make(const char *tag)
{
    snprintf(g_root, sizeof(g_root), "/tmp/l2srt-%s-%d", tag, (int)getpid());
    rm_tree(g_root);
    if (mkdir(g_root, 0700) != 0) {
        fprintf(stderr, "cannot create sandbox %s: %s\n", g_root, strerror(errno));
        exit(2);
    }
}

static void sandbox_drop(void)
{
    rm_tree(g_root);
}

/* 在沙箱里拼一个绝对路径 */
static void sp(char *out, size_t outsz, const char *rel)
{
    int n = snprintf(out, outsz, "%s/%s", g_root, rel);
    if (n < 0 || (size_t)n >= outsz) {
        fprintf(stderr, "sandbox path too long: %s/%s\n", g_root, rel);
        exit(2);
    }
}

static void write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
        exit(2);
    }
    fputs(text, f);
    fclose(f);
}

static void read_file(const char *path, char *out, size_t outsz)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (f == NULL) {
        out[0] = '\0';
        return;
    }
    n = fread(out, 1, outsz - 1, f);
    out[n] = '\0';
    fclose(f);
}

/*
 * 用 l2s_dir = NULL（中间层生成在原文件旁边）建配置。
 * 这样中间层与数据文件都在沙箱内，便于直接观察。
 */
static l2s_config cfg_beside(void)
{
    l2s_config c = L2S_CONFIG_DEFAULT;
    c.l2s_dir = NULL;
    c.scheme = L2S_SCHEME_PROOT;
    return c;
}

/* 用集中目录（模拟 DSHA 生产的 PROOT_L2S_DIR） */
static l2s_config cfg_central(void)
{
    static char dir[PATH_MAX];
    l2s_config c = L2S_CONFIG_DEFAULT;
    sp(dir, sizeof(dir), ".l2s");
    mkdir(dir, 0700);
    c.l2s_dir = dir;
    /*
     * 必须与生产一致：L2S_SCHEME_PROOT。
     *
     * 这里原先写的是 L2S_SCHEME_PROROOT，于是测试台的配置与真实部署
     * 不同 —— 第一次链接照样成功（建档不经过分类器），所以看不出来；
     * 第二次链接才暴露出分类器认不出中间层。测试配错 scheme 等于
     * 用一把假钥匙去试锁。
     */
    c.scheme = L2S_SCHEME_PROOT;
    return c;
}

/* ================================================================== */
/* A1. 首次链接：内容搬家 + 三层结构                                    */
/* ================================================================== */

static void t_first_link(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX], mid[PATH_MAX], final[PATH_MAX];
    char buf[256];
    struct stat st;
    int rc;

    CASE("A1 首次链接建立三层结构，两个客户路径都能读到内容");
    sandbox_make("first");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "a.txt");
    sp(b, sizeof(b), "b.txt");
    write_file(a, "hello-l2s");

    rc = l2s_rt_link(a, b);
    CHECK_EQ_I(rc, 0);

    /* 两个客户路径都能读到同一份内容 */
    read_file(a, buf, sizeof(buf));
    CHECK(strcmp(buf, "hello-l2s") == 0);
    read_file(b, buf, sizeof(buf));
    CHECK(strcmp(buf, "hello-l2s") == 0);

    /* a 和 b 都应是符号链接（伪造硬链接在磁盘上就是符号链接） */
    CHECK(lstat(a, &st) == 0 && S_ISLNK(st.st_mode));
    CHECK(lstat(b, &st) == 0 && S_ISLNK(st.st_mode));

    /* 用 l2s 纯逻辑算出期望的中间层与数据文件路径，逐一核对 */
    rc = l2s_make_paths_ex(&cfg, a, 1, 2, NULL, mid, final);
    CHECK_EQ_I(rc, L2S_OK);
    CHECK(lstat(mid, &st) == 0 && S_ISLNK(st.st_mode));   /* 中间层是链接 */
    CHECK(lstat(final, &st) == 0 && S_ISREG(st.st_mode)); /* 数据文件是普通文件 */
    read_file(final, buf, sizeof(buf));
    CHECK(strcmp(buf, "hello-l2s") == 0);

    CHECK_EQ_I(l2s_rt_get_stats()->link_first, 1);
    sandbox_drop();
}

/* ================================================================== */
/* A2. 后续链接：链接数递增，数据文件改名                               */
/* ================================================================== */

static void t_more_links(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX], mid[PATH_MAX], f2[PATH_MAX];
    char buf[256];
    struct stat st;
    int rc;

    CASE("A2 再次链接只改旁路计数，数据文件名恒定不变");
    sandbox_make("more");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "x");
    sp(b, sizeof(b), "y");
    sp(c, sizeof(c), "z");
    write_file(a, "shared");

    /* 首次链接：代号 1、初始链接数 2 */
    CHECK_EQ_I(l2s_rt_link(a, b), 0);
    rc = l2s_make_paths_ex(&cfg, a, 1, 2, NULL, mid, f2);
    CHECK_EQ_I(rc, L2S_OK);
    CHECK(lstat(f2, &st) == 0 && S_ISREG(st.st_mode));

    /* 记住数据文件的 inode 与 mtime，稍后证明它没被搬动过 */
    struct stat before;
    CHECK(lstat(f2, &before) == 0);

    CHECK_EQ_I(l2s_rt_link(a, c), 0);

    /* 三条路径都读得到 */
    read_file(a, buf, sizeof(buf)); CHECK(strcmp(buf, "shared") == 0);
    read_file(b, buf, sizeof(buf)); CHECK(strcmp(buf, "shared") == 0);
    read_file(c, buf, sizeof(buf)); CHECK(strcmp(buf, "shared") == 0);

    /*
     * 核心不变式：数据文件的路径名、inode 都没变。
     * 这正是不触发官方运行时缓存缺陷的充要条件。
     */
    {
        struct stat after;
        CHECK(lstat(f2, &after) == 0);          /* 同一个名字仍在 */
        CHECK_EQ_I(after.st_ino, before.st_ino); /* 同一个 inode */
    }

    /* 旁路计数应为 3 */
    {
        char cnt[PATH_MAX], cbuf[32];
        size_t clen = 0;
        CHECK_EQ_I(l2s_refcount_path(f2, cnt, sizeof(cnt)), L2S_OK);
        CHECK_EQ_I(REAL_OPS.read_small(cnt, cbuf, sizeof(cbuf), &clen), 0);
        cbuf[clen] = '\0';
        CHECK(strcmp(cbuf, "3") == 0);
    }

    CHECK_EQ_I(l2s_rt_get_stats()->link_first, 1);
    CHECK_EQ_I(l2s_rt_get_stats()->link_more, 1);
    sandbox_drop();
}

/* ================================================================== */
/* A3. unlink 递减                                                      */
/* ================================================================== */

static void t_unlink_decrement(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX];
    char buf[256];
    struct stat st;
    char f3[PATH_MAX], mid[PATH_MAX];
    int rc;

    CASE("A3 删掉一条链接只是递减旁路计数，其余路径仍可读");
    sandbox_make("unlink");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "p");
    sp(b, sizeof(b), "q");
    sp(c, sizeof(c), "r");
    write_file(a, "payload");

    CHECK_EQ_I(l2s_rt_link(a, b), 0);
    CHECK_EQ_I(l2s_rt_link(a, c), 0);

    rc = l2s_make_paths_ex(&cfg, a, 1, 2, NULL, mid, f3);
    CHECK_EQ_I(rc, L2S_OK);

    /* 删 c：链长 3 -> 2 */
    CHECK_EQ_I(l2s_rt_unlink(c), 0);
    CHECK(lstat(c, &st) != 0);              /* c 没了 */
    read_file(a, buf, sizeof(buf)); CHECK(strcmp(buf, "payload") == 0);
    read_file(b, buf, sizeof(buf)); CHECK(strcmp(buf, "payload") == 0);
    CHECK(lstat(f3, &st) == 0 && S_ISREG(st.st_mode));

    /* 删 b：链长 2 -> 1 */
    CHECK_EQ_I(l2s_rt_unlink(b), 0);
    read_file(a, buf, sizeof(buf)); CHECK(strcmp(buf, "payload") == 0);

    /* 删 a：最后一条，中间层与数据文件都回收 */
    CHECK_EQ_I(l2s_rt_unlink(a), 0);
    CHECK(lstat(a, &st) != 0);
    CHECK(lstat(mid, &st) != 0);   /* 中间层没了 */
    CHECK(lstat(f3, &st) != 0);    /* 数据文件也没了 */

    CHECK_EQ_I(l2s_rt_get_stats()->unlink_dec, 2);
    CHECK_EQ_I(l2s_rt_get_stats()->unlink_free, 1);
    sandbox_drop();
}

/* ================================================================== */
/* A3b. 针对官方 proroot 运行时缺陷的回归用例（本项目的存在理由之一）    */
/* ================================================================== */

static void t_no_rename_regression(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX], mid[PATH_MAX], fin[PATH_MAX];
    char buf[256];
    struct stat before, after;
    int rc;

    CASE("A3b 回归：加链长不得改动数据文件名（否则命中官方运行时缓存缺陷）");
    sandbox_make("norename");
    l2s_rt_init(&REAL_OPS, &cfg);

    sp(a, sizeof(a), "orig");
    sp(b, sizeof(b), "l1");
    sp(c, sizeof(c), "l2");
    write_file(a, "content");

    CHECK_EQ_I(l2s_rt_link(a, b), 0);
    rc = l2s_make_paths_ex(&cfg, a, 1, 2, NULL, mid, fin);
    CHECK_EQ_I(rc, L2S_OK);
    CHECK(lstat(fin, &before) == 0);

    /*
     * 先真读一次 —— 这正是官方运行时建立路径缓存的时机。
     * 换成 proot 的旧设计（加链长时 rename 数据文件），
     * 下面这次读取会返回 ENOENT。
     */
    read_file(a, buf, sizeof(buf));
    CHECK(strcmp(buf, "content") == 0);

    CHECK_EQ_I(l2s_rt_link(a, c), 0);   /* 加链长 */

    /* 数据文件必须还在原处、还是同一个 inode */
    CHECK(lstat(fin, &after) == 0);
    CHECK_EQ_I(after.st_ino, before.st_ino);

    /* 老路径照样能读 —— 这就是缺陷不再触发的直接证据 */
    read_file(a, buf, sizeof(buf));
    CHECK(strcmp(buf, "content") == 0);
    read_file(b, buf, sizeof(buf));
    CHECK(strcmp(buf, "content") == 0);
    read_file(c, buf, sizeof(buf));
    CHECK(strcmp(buf, "content") == 0);

    sandbox_drop();
}

/* ================================================================== */
/* A4. readlink 反转译                                                  */
/* ================================================================== */

/*
 * A11. `patch_stat` 必须回填**真实文件大小**，而不是符号链接自身的长度。
 *
 * 【为什么这条必须单独测】
 *
 * `l2s_rt_patch_stat` 修的是「让伪造链接看起来像真实硬链接」。此前的实现
 * 只改 `st_nlink` 与 `st_mode` 的 S_IFLNK 位，**其余字段保持内核给的** ——
 * 而内核给的是**符号链接的** stat，于是：
 *
 *     st_size = 符号链接目标字符串的长度（几十字节）
 *     真实文件可能只有 5 字节
 *
 * 【后果（实测，不是理论）】
 * 用真实工具链探针发现的：
 *     tar tvf → 把伪造链接按**符号链接**归档，并把**宿主绝对路径**写进归档
 *     cp -a  → 直接失败
 * 官方 proroot 在同场景下 `tar` 输出的是普通文件、大小正确。
 *
 * 【PRoot 的做法（权威参照）】
 * `src/extension/link2symlink/link2symlink.c:860-890` —— 它是**整体替换**
 * 客户的 `struct stat` 为**数据文件的**，只保留 `mode` / `uid` / `gid`。
 * 所以 `st_size` / `st_ino` / `st_blocks` 全部来自数据文件。
 *
 * 【本测试钉住什么】
 *   ① `st_size` 等于真实内容长度（不是链接目标的长度）
 *   ② 普通文件不受影响（其 size 本就是对的）
 *   ③ `st_nlink` / `st_mode` 的既有行为不回归
 */
static void t_stat_size_is_real(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX];
    struct stat st;
    const char *content = "hello";     /* 5 字节 —— 与链接目标长度差别明显 */

    CASE("A11 patch_stat 回填真实 size（不是链接长度）");
    sandbox_make("statsize");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "s.txt");
    sp(b, sizeof(b), "t.txt");
    write_file(a, content);
    CHECK_EQ_I(l2s_rt_link(a, b), 0);

    /* 内核视角：符号链接，其 st_size 是**目标字符串长度**（远大于 5） */
    CHECK(lstat(a, &st) == 0);
    CHECK(S_ISLNK(st.st_mode));
    {
        /*
         * 先确认"内核给的 size 确实不等于内容长度" —— 否则本测试没有
         * 判别力（若链接目标恰好 5 字节，就测不出回填是否发生）。
         * 这是一个**前提断言**：它保证下面的断言有意义。
         */
        CHECK(st.st_size != (off_t)strlen(content));
    }

    /* 客户视角：普通文件，size 必须是真实内容长度 */
    l2s_rt_patch_stat(&st, a);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_I(st.st_nlink, 2);
    CHECK_EQ_I(st.st_size, (off_t)strlen(content));

    /* 普通文件不受影响 */
    {
        char plain[PATH_MAX];
        struct stat pst;
        sp(plain, sizeof(plain), "plainfile");
        write_file(plain, content);
        CHECK(lstat(plain, &pst) == 0);
        l2s_rt_patch_stat(&pst, plain);
        CHECK(S_ISREG(pst.st_mode));
        CHECK_EQ_I(pst.st_size, (off_t)strlen(content));
        CHECK_EQ_I(pst.st_nlink, 1);
    }

    sandbox_drop();
}

/*
 * A4. readlink 对伪造链接返回「失败」哨兵（2026-09-16 语义反转）
 *
 * 【本用例为什么改了断言（原断言固化的是缺陷行为）】
 *
 * 原断言要求：
 *     rc == 1                        （改写成功）
 *     strstr(out, "orig.txt") != NULL（还原出客户本来的名字）
 * 即把「readlink 成功返回一个客户名」当成期望行为。
 *
 * 实测证明那个返回值会造成**数据完整性缺陷**：
 *   - 客户的 lstat 说 S_IFREG（本层抹掉了 S_IFLNK），而 readlink 却成功
 *     —— 两个信号自相矛盾，工具据此判定"它是符号链接"
 *   - `tar cf`   → 按符号链接归档，并把**宿主绝对路径**
 *                  （/data/data/com.dsh.client/files/...）写进归档
 *   - `cp -a`    → ELOOP（cp 拿 readlink 的结果自己去解析，形成自环）
 * 官方 proroot 对同一路径返回 EINVAL（它不刻意如此，而是因为它在
 * 系统调用入口就把伪造链接换成了数据文件，内核看到的已是普通文件）。
 *
 * 所以断言改为反映**新契约**：命中伪造链接 → L2S_RT_READLINK_FAKE。
 * 后半段（用户自己的真符号链接不被改写）保持不变 —— 那是必须守住的
 * 回归点，也是一刀切关掉 readlink 时最容易破坏的地方。
 */
static void t_readlink_rewrite(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX];
    char raw[PATH_MAX], out[PATH_MAX];
    ssize_t n;
    int rc;

    CASE("A4 readlink 对伪造链接报告失败哨兵，真符号链接不受影响");
    sandbox_make("readlink");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "orig.txt");
    sp(b, sizeof(b), "link.txt");
    write_file(a, "data");

    CHECK_EQ_I(l2s_rt_link(a, b), 0);

    /* 内核返回的是中间层路径 */
    n = readlink(a, raw, sizeof(raw) - 1);
    CHECK(n > 0);
    if (n > 0) {
        raw[n] = '\0';
        /* 内核视角确实带 l2s 装饰 */
        CHECK(strstr(raw, ".l2s.") != NULL);

        /*
         * 客户视角：a 是普通文件，readlink 必须失败。
         * 返回 L2S_RT_READLINK_FAKE，由钩子转成 errno=EINVAL。
         */
        rc = l2s_rt_rewrite_readlink(a, raw, out, sizeof(out));
        CHECK_EQ_I(rc, L2S_RT_READLINK_FAKE);
    }

    /* 同一个链的第二个名字也必须失败（两条都是伪造链接） */
    {
        char raw2[PATH_MAX];
        n = readlink(b, raw2, sizeof(raw2) - 1);
        CHECK(n > 0);
        if (n > 0) {
            raw2[n] = '\0';
            rc = l2s_rt_rewrite_readlink(b, raw2, out, sizeof(out));
            CHECK_EQ_I(rc, L2S_RT_READLINK_FAKE);
        }
    }

    /*
     * 用户自己的普通符号链接**必须仍然正常**（rc == 0 → 调用方透传
     * 内核结果）。这是修复"伪造链接的 readlink 应失败"时最容易破坏的
     * 一点：一刀切地让 readlink 全部失败，就会把正常功能一起关掉。
     */
    {
        char plain_link[PATH_MAX], plain_tgt[PATH_MAX];
        sp(plain_link, sizeof(plain_link), "plain");
        CHECK(symlink("orig.txt", plain_link) == 0);
        n = readlink(plain_link, plain_tgt, sizeof(plain_tgt) - 1);
        CHECK(n > 0);
        if (n > 0) {
            plain_tgt[n] = '\0';
            rc = l2s_rt_rewrite_readlink(plain_link, plain_tgt, out, sizeof(out));
            CHECK_EQ_I(rc, 0);                   /* 不碰 */
        }
    }

    sandbox_drop();
}

/* ================================================================== */
/* A5. stat 补丁：伪造链接看起来像真硬链接                              */
/* ================================================================== */

static void t_stat_patch(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX];
    struct stat st;

    CASE("A5 stat 报出链长而不是 1，且不再是符号链接");
    sandbox_make("stat");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "s1");
    sp(b, sizeof(b), "s2");
    sp(c, sizeof(c), "s3");
    write_file(a, "body");
    CHECK_EQ_I(l2s_rt_link(a, b), 0);
    CHECK_EQ_I(l2s_rt_link(a, c), 0);

    /* 内核视角：符号链接，nlink 为 1 */
    CHECK(lstat(a, &st) == 0);
    CHECK(S_ISLNK(st.st_mode));
    CHECK_EQ_I(st.st_nlink, 1);

    /* 客户视角：普通文件，nlink 3 */
    l2s_rt_patch_stat(&st, a);
    CHECK(S_ISREG(st.st_mode));
    CHECK_EQ_I(st.st_nlink, 3);

    /* 普通文件不受影响 */
    {
        char plain[PATH_MAX];
        struct stat pst;
        sp(plain, sizeof(plain), "notalink");
        write_file(plain, "x");
        CHECK(lstat(plain, &pst) == 0);
        l2s_rt_patch_stat(&pst, plain);
        CHECK(S_ISREG(pst.st_mode));
        CHECK_EQ_I(pst.st_nlink, 1);
    }

    CHECK(l2s_rt_get_stats()->nlink_patched >= 1);
    sandbox_drop();
}

/* ================================================================== */
/* A6. 集中目录布局（DSHA 生产的 PROOT_L2S_DIR）                        */
/* ================================================================== */

static void t_central_dir(void)
{
    l2s_config cfg = cfg_central();
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX], mid[PATH_MAX], final[PATH_MAX];
    char buf[256];
    struct stat st;
    int rc;

    CASE("A6 集中目录布局：中间层落在 PROOT_L2S_DIR 里，不在文件旁边");
    sandbox_make("central");
    cfg = cfg_central();           /* 沙箱换过了，重建 */
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "f1");
    sp(b, sizeof(b), "f2");
    write_file(a, "central");

    CHECK_EQ_I(l2s_rt_link(a, b), 0);
    read_file(a, buf, sizeof(buf)); CHECK(strcmp(buf, "central") == 0);
    read_file(b, buf, sizeof(buf)); CHECK(strcmp(buf, "central") == 0);

    /* 中间层必须在集中目录里 */
    rc = l2s_make_paths_ex(&cfg, a, 1, 2, NULL, mid, final);
    CHECK_EQ_I(rc, L2S_OK);
    CHECK(strncmp(mid, cfg.l2s_dir, strlen(cfg.l2s_dir)) == 0);
    CHECK(lstat(mid, &st) == 0);
    CHECK(lstat(final, &st) == 0 && S_ISREG(st.st_mode));
    read_file(final, buf, sizeof(buf));
    CHECK(strcmp(buf, "central") == 0);

    /*
     * 必须再做一次链接。
     *
     * 这一条是被真实事故补上的：集中目录布局下，第二次 link() 依赖
     * l2s_classify() 能识别出第一种命名形状。曾经因为 scheme 配错，
     * 分类器不去解析它，resolve_final() 认不出数据文件，第二次链接
     * 直接失败 —— 而当时的 A6 只做了一次链接，完全没覆盖到，
     * 测试全绿却漏掉了这个必然失败的生产路径。
     */
    sp(c, sizeof(c), "f3");
    CHECK_EQ_I(l2s_rt_link(a, c), 0);
    read_file(c, buf, sizeof(buf));
    CHECK(strcmp(buf, "central") == 0);
    CHECK_EQ_I(l2s_rt_get_stats()->link_more, 1);

    /* 链长应报 3 */
    {
        struct stat cst;
        CHECK(lstat(a, &cst) == 0);
        l2s_rt_patch_stat(&cst, a);
        CHECK_EQ_I(cst.st_nlink, 3);
    }

    sandbox_drop();
}

/* ================================================================== */
/* A7. 两个客户路径互相链接（链的正常用法）                              */
/* ================================================================== */

static void t_link_from_fake(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX];
    char buf[256];
    struct stat st;

    CASE("A7 从一个已是伪造链接的路径再链接，仍走加链长分支");
    sandbox_make("fromfake");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "base");
    sp(b, sizeof(b), "one");
    sp(c, sizeof(c), "two");
    write_file(a, "shared-body");

    CHECK_EQ_I(l2s_rt_link(a, b), 0);   /* 首次 */
    CHECK_EQ_I(l2s_rt_link(b, c), 0);   /* b 已是伪造链接 -> 加链长 */

    read_file(a, buf, sizeof(buf)); CHECK(strcmp(buf, "shared-body") == 0);
    read_file(b, buf, sizeof(buf)); CHECK(strcmp(buf, "shared-body") == 0);
    read_file(c, buf, sizeof(buf)); CHECK(strcmp(buf, "shared-body") == 0);

    CHECK(lstat(a, &st) == 0);
    l2s_rt_patch_stat(&st, a);
    CHECK_EQ_I(st.st_nlink, 3);

    CHECK_EQ_I(l2s_rt_get_stats()->link_first, 1);
    CHECK_EQ_I(l2s_rt_get_stats()->link_more, 1);
    sandbox_drop();
}

/* ================================================================== */
/* A8. 目录不能被链接                                                   */
/* ================================================================== */

static void t_dir_refused(void)
{
    l2s_config cfg = cfg_beside();
    char d[PATH_MAX], l[PATH_MAX];
    int rc;

    CASE("A8 目录链接被拒（EPERM），与真实 link(2) 一致");
    sandbox_make("dirref");
    l2s_rt_init(&REAL_OPS, &cfg);

    sp(d, sizeof(d), "adir");
    sp(l, sizeof(l), "alink");
    CHECK(mkdir(d, 0700) == 0);

    rc = l2s_rt_link(d, l);
    CHECK_EQ_I(rc, -EPERM);
    sandbox_drop();
}

/* ================================================================== */
/* A9. 非伪造路径一律透传                                               */
/* ================================================================== */

static void t_passthru(void)
{
    l2s_config cfg = cfg_beside();
    char a[PATH_MAX];
    struct stat st;

    CASE("A9 非伪造路径的 unlink/rename 透传；link 则是模拟入口");
    sandbox_make("pass");
    l2s_rt_init(&REAL_OPS, &cfg);
    l2s_rt_reset_stats();

    sp(a, sizeof(a), "ordinary");
    write_file(a, "z");

    /*
     * 先厘清语义，早先这里的断言写反了：
     *
     *   - unlink / rename 一个**普通**文件：与 l2s 无关，透传。
     *   - link 一个普通文件：这**正是** l2s 的入口 —— 要把它改造成
     *     伪造硬链接。所以它必须被接管，返回 0 而不是透传。
     *
     * 把 link 也断言成透传，等于要求整个模拟层不工作。
     */
    {
        char dst[PATH_MAX];
        sp(dst, sizeof(dst), "ordinary2");

        CHECK_EQ_I(l2s_rt_unlink(a), L2S_RT_PASSTHRU);   /* 还没建链，透传 */
        CHECK_EQ_I(l2s_rt_rename(a, dst), L2S_RT_PASSTHRU);

        /* 透传不该改动文件 */
        CHECK(lstat(a, &st) == 0 && S_ISREG(st.st_mode));
        CHECK_EQ_I((long)l2s_rt_get_stats()->link_first, 0);
        CHECK_EQ_I((long)l2s_rt_get_stats()->nlink_patched, 0);

        /* 现在正式建链：这一步必须被接管 */
        CHECK_EQ_I(l2s_rt_link(a, dst), 0);
        CHECK_EQ_I((long)l2s_rt_get_stats()->link_first, 1);

        /* 建完之后 a 变成伪造链接，此时 unlink 才该被接管 */
        CHECK_EQ_I(l2s_rt_unlink(a), 0);
    }
    sandbox_drop();
}

/* ================================================================== */
/* A10. 未初始化 / 未启用时全部透传                                     */
/* ================================================================== */

static void t_disabled(void)
{
    char a[PATH_MAX];

    CASE("A10 关闭后所有操作透传（安全默认值）");
    sandbox_make("disabled");

    /*
     * 前面的用例已经 init 过，g_enabled 是 1。要测「未启用」这条路，
     * 必须先显式 shutdown —— 否则这条断言测的是前一个用例的残留状态。
     */
    l2s_rt_shutdown();
    sp(a, sizeof(a), "whatever");
    write_file(a, "q");

    {
        char dst[PATH_MAX];
        sp(dst, sizeof(dst), "whatever2");
        CHECK_EQ_I(l2s_rt_enabled(), 0);
        CHECK_EQ_I(l2s_rt_link(a, dst), L2S_RT_PASSTHRU);
        CHECK_EQ_I(l2s_rt_unlink(a), L2S_RT_PASSTHRU);
    }
    {
        l2s_config back = cfg_beside();
        l2s_rt_init(&REAL_OPS, &back);   /* 复位，免得影响后续用例 */
    }
    sandbox_drop();
}

/* ================================================================== */
/* B. 故障注入：内存 FS                                                */
/* ================================================================== */

/*
 * 一个极小的内存 FS，只够模拟符号链接与目录项。用途是精确制造错误，
 * 这些错误在真实 f2fs 上很难触发（例如 ENOSPC、rename 失败）。
 */
#define MFS_MAX 64

typedef struct {
    char name[128];      /* 仅 basename */
    int is_link;
    char target[256];    /* is_link 时有效 */
} mfs_ent;

static mfs_ent g_mfs[MFS_MAX];
static int g_mfs_n;
static int g_fail_on;       /* 让指定操作失败 */
static int g_fail_errno;

#define FAIL_RENAME 1
#define FAIL_SYMLINK 2
#define FAIL_LSTAT 3

static mfs_ent *mfs_find(const char *path)
{
    const char *b = strrchr(path, '/');
    int i;
    b = b == NULL ? path : b + 1;
    for (i = 0; i < g_mfs_n; i++)
        if (strcmp(g_mfs[i].name, b) == 0)
            return &g_mfs[i];
    return NULL;
}

static mfs_ent *mfs_add(const char *path)
{
    mfs_ent *e;
    const char *b = strrchr(path, '/');
    if (g_mfs_n >= MFS_MAX)
        return NULL;
    e = &g_mfs[g_mfs_n++];
    b = b == NULL ? path : b + 1;
    snprintf(e->name, sizeof(e->name), "%s", b);
    e->is_link = 0;
    e->target[0] = '\0';
    return e;
}

static int mfs_lstat(const char *p, struct stat *st)
{
    mfs_ent *e;
    if (g_fail_on == FAIL_LSTAT) { errno = g_fail_errno; return -1; }
    e = mfs_find(p);
    if (e == NULL) { errno = ENOENT; return -1; }
    memset(st, 0, sizeof(*st));
    st->st_mode = e->is_link ? S_IFLNK : S_IFREG;
    st->st_nlink = 1;
    return 0;
}

static int mfs_symlink(const char *t, const char *l)
{
    mfs_ent *e;
    if (g_fail_on == FAIL_SYMLINK) { errno = g_fail_errno; return -1; }
    if (mfs_find(l) != NULL) { errno = EEXIST; return -1; }
    e = mfs_add(l);
    if (e == NULL) { errno = ENOSPC; return -1; }
    e->is_link = 1;
    snprintf(e->target, sizeof(e->target), "%s", t);
    return 0;
}

static int mfs_rename(const char *o, const char *n)
{
    mfs_ent *e;
    if (g_fail_on == FAIL_RENAME) { errno = g_fail_errno; return -1; }
    e = mfs_find(o);
    if (e == NULL) { errno = ENOENT; return -1; }
    {
        const char *b = strrchr(n, '/');
        b = b == NULL ? n : b + 1;
        snprintf(e->name, sizeof(e->name), "%s", b);
    }
    return 0;
}

static int mfs_unlink(const char *p)
{
    int i;
    mfs_ent *e = mfs_find(p);
    if (e == NULL) { errno = ENOENT; return -1; }
    i = (int)(e - g_mfs);
    memmove(&g_mfs[i], &g_mfs[i + 1],
            (size_t)(g_mfs_n - i - 1) * sizeof(g_mfs[0]));
    g_mfs_n--;
    return 0;
}

static ssize_t mfs_readlink(const char *p, char *b, size_t s)
{
    mfs_ent *e = mfs_find(p);
    size_t n;
    if (e == NULL || !e->is_link) { errno = EINVAL; return -1; }
    n = strlen(e->target);
    if (n > s) n = s;
    memcpy(b, e->target, n);
    return (ssize_t)n;
}

static int mfs_access(const char *p, int m)
{
    (void)m;
    if (mfs_find(p) == NULL) { errno = ENOENT; return -1; }
    return 0;
}

/* 内存 FS 的旁路小文件：单独一张表，避免与目录项混淆 */
#define MFS_SMALL_MAX 32
typedef struct { char name[128]; char data[32]; size_t len; } mfs_small;
static mfs_small g_small[MFS_SMALL_MAX];
static int g_small_n;

static mfs_small *small_find(const char *p)
{
    const char *b = strrchr(p, '/');
    int i;
    b = b == NULL ? p : b + 1;
    for (i = 0; i < g_small_n; i++)
        if (strcmp(g_small[i].name, b) == 0)
            return &g_small[i];
    return NULL;
}

static int mfs_read_small(const char *p, char *buf, size_t bufsz, size_t *out_len)
{
    mfs_small *e = small_find(p);
    if (e == NULL)
        return -ENOENT;
    if (e->len + 1 > bufsz)
        return -ENAMETOOLONG;
    memcpy(buf, e->data, e->len);
    buf[e->len] = '\0';
    *out_len = e->len;
    return 0;
}

static int mfs_write_small(const char *p, const char *buf, size_t len)
{
    mfs_small *e = small_find(p);
    if (e == NULL) {
        const char *b = strrchr(p, '/');
        if (g_small_n >= MFS_SMALL_MAX)
            return -ENOSPC;
        e = &g_small[g_small_n++];
        b = b == NULL ? p : b + 1;
        snprintf(e->name, sizeof(e->name), "%s", b);
    }
    if (len >= sizeof(e->data))
        return -ENAMETOOLONG;
    memcpy(e->data, buf, len);
    e->len = len;
    return 0;
}

static const l2s_rt_ops MFS_OPS = {
    mfs_lstat, mfs_symlink, mfs_rename, mfs_unlink, mfs_readlink, mfs_access,
    mfs_read_small, mfs_write_small
};

static void mfs_reset(void)
{
    memset(g_mfs, 0, sizeof(g_mfs));
    g_mfs_n = 0;
    memset(g_small, 0, sizeof(g_small));
    g_small_n = 0;
    g_fail_on = 0;
    g_fail_errno = 0;
}

/* ================================================================== */
/* B1. 首次链接时 rename 失败 -> 报错且不留残骸                          */
/* ================================================================== */

static void t_fail_rename(void)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    int rc;

    CASE("B1 首次链接中 rename 失败：如实上抛 errno，不当成功");
    mfs_reset();
    cfg.l2s_dir = NULL;
    l2s_rt_init(&MFS_OPS, &cfg);

    mfs_add("/w/a");
    g_fail_on = FAIL_RENAME;
    g_fail_errno = ENOSPC;

    rc = l2s_rt_link("/w/a", "/w/b");
    CHECK_EQ_I(rc, -ENOSPC);
    CHECK_EQ_I(g_mfs_n, 1);   /* 没有留下中间层或数据文件 */
}

/* ================================================================== */
/* B2. 中间层建链失败 -> 回滚，原文件回到原位                            */
/* ================================================================== */

static void t_rollback_symlink(void)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    mfs_ent *e;
    int rc;

    CASE("B2 中间层 symlink 失败：数据文件被搬回原位，客户文件不丢");
    mfs_reset();
    cfg.l2s_dir = NULL;
    l2s_rt_init(&MFS_OPS, &cfg);

    mfs_add("/w/a");
    g_fail_on = FAIL_SYMLINK;
    g_fail_errno = EACCES;

    rc = l2s_rt_link("/w/a", "/w/b");
    CHECK_EQ_I(rc, -EACCES);

    /* 关键：原始数据必须回到 /w/a，不能因为中途失败而丢文件 */
    e = mfs_find("/w/a");
    CHECK(e != NULL);
    g_fail_on = 0;
    if (e != NULL) {
        struct stat st;
        CHECK_EQ_I(mfs_lstat("/w/a", &st), 0);
        CHECK(S_ISREG(st.st_mode));   /* 还是那个普通文件，不是悬空链接 */
    }
}

/* ================================================================== */
/* B3. 链已损坏时的 unlink 不报错（反正是要删的）                        */
/* ================================================================== */

static void t_broken_chain(void)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    int rc;

    CASE("B3 链损坏时 unlink 仍能删掉客户路径，不把错误甩给用户");
    mfs_reset();
    cfg.l2s_dir = NULL;
    l2s_rt_init(&MFS_OPS, &cfg);

    /* 建一个指向不存在中间层的悬空链接 */
    CHECK_EQ_I(mfs_symlink("/w/.l2s.gone0001", "/w/broken"), 0);

    rc = l2s_rt_unlink("/w/broken");
    CHECK_EQ_I(rc, 0);
    CHECK(mfs_find("/w/broken") == NULL);
}

/* ================================================================== */
/* B4. 链接数上溢                                                      */
/* ================================================================== */

static void t_nlink_overflow(void)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    int rc;

    CASE("B4 链接数达到 9999 上限时拒绝再加，返回 EMLINK");
    mfs_reset();
    cfg.l2s_dir = NULL;
    l2s_rt_init(&MFS_OPS, &cfg);

    /* 搭一条链：中间层 -> 数据文件，客户路径 -> 中间层 */
    CHECK_EQ_I(mfs_symlink("/w/.l2s.a0001.0002", "/w/.l2s.a0001"), 0);
    CHECK_EQ_I(mfs_symlink("/w/.l2s.a0001", "/w/a"), 0);
    /* 旁路计数已经写满 */
    CHECK_EQ_I(mfs_write_small("/w/.l2s.a0001.0002.cnt", "9999", 4), 0);

    rc = l2s_rt_link("/w/a", "/w/b");
    CHECK_EQ_I(rc, -EMLINK);
}

/* ================================================================== */
/* main                                                                */
/* ================================================================== */

int main(void)
{
    printf("l2s 运行时层测试\n");
    printf("沙箱根：/tmp/l2srt-*（真实 f2fs，符号链接可用）\n");
    printf("========================================\n");

    printf("\n[A] 真实文件系统端到端\n");
    t_first_link();
    t_more_links();
    t_unlink_decrement();
    t_no_rename_regression();
    t_readlink_rewrite();
    t_stat_patch();
    t_stat_size_is_real();
    t_central_dir();
    t_link_from_fake();
    t_dir_refused();
    t_passthru();
    t_disabled();

    printf("\n[B] 故障注入\n");
    t_fail_rename();
    t_rollback_symlink();
    t_broken_chain();
    t_nlink_overflow();

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d failed)\n", g_cases, g_failed);
    printf("checks: %d  (%d failed)\n", g_checks, g_failed);
    printf("RESULT: %s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}
