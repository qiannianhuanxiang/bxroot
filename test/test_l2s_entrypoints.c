/*
 * test_l2s_entrypoints.c —— l2s stat 伪装的**多入口**契约测试
 *
 * ====================================================================
 * 为什么必须单独有这样一个测试
 * ====================================================================
 *
 * `test/test_l2s_rt.c`（119 断言）测的是 l2s 库**自身**的逻辑 —— 注入
 * 一个内存文件系统，直接调 l2s_rt_patch_stat()。它全绿，却完全测不到
 * "运行时层有没有把钩子接上"。
 *
 * 本轮真实缺陷恰恰全在**接线**上，而且是**三个不同入口各坏一处**：
 *
 *   ① cfg.scheme 传成 PROROOT，而 l2s-runtime 只会写 PROOT 式名字
 *      → probe_fake_link() 永远返回 0，patch 静默不生效
 *   ② fstatat 钩子漏了 l2s_rt_patch_stat 调用
 *      （stat/lstat/stat64/lstat64 都有，fstatat 是唯一漏的）
 *   ③ node/libuv 的 uv__fs_statx() **故意绕开 libc**，走裸
 *      syscall(SYS_statx)；接在 libc statx() 钩子上对 node 完全无效
 *
 * 教训：**"能力已实现"不等于"能力已生效"**。只测库函数会漏掉接线，
 * 只测单一入口会漏掉"客户其实不走这条路"。
 *
 * 本测试因此做两件事：
 *   A. 逐入口列清单（哪些入口存在、哪些缺失），缺一个就报出来；
 *   B. 用**真实文件系统 + 真实 l2s 库**验证 scheme 不变量的行为契约。
 *
 * ====================================================================
 * 用法
 * ====================================================================
 *   sh test/RUN_L2S_ENTRYPOINTS.sh        （推荐，自动编译并跑）
 *   或
 *   gcc -O0 -D_GNU_SOURCE= -Isrc/l2s -o /tmp/t test/test_l2s_entrypoints.c \
 *       src/l2s/l2s.c src/l2s/l2s-runtime.c && /tmp/t
 *
 * 退出码：0 = 全部通过；1 = 有失败。
 *
 * SPDX-License-Identifier: MIT
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "l2s.h"
#include "l2s-runtime.h"

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, ...)                                                      \
    do {                                                                      \
        if (cond) {                                                           \
            g_pass++;                                                         \
        } else {                                                              \
            g_fail++;                                                         \
            printf("  ❌ %s:%d  ", __FILE__, __LINE__);                       \
            printf(__VA_ARGS__);                                              \
            printf("\n");                                                     \
        }                                                                     \
    } while (0)

#define CASE(name) printf("▶ %s\n", name)

/* ------------------------------------------------------------------ */
/* 注入 ops：真实 FS                                                    */
/* ------------------------------------------------------------------ */

static int o_lstat(const char *p, struct stat *st) { return lstat(p, st); }
static int o_symlink(const char *t, const char *l) { return symlink(t, l); }
static int o_rename(const char *o, const char *n) { return rename(o, n); }
static int o_unlink(const char *p) { return unlink(p); }
static ssize_t o_readlink(const char *p, char *b, size_t sz)
{
    return readlink(p, b, sz);
}
static int o_access(const char *p, int m) { return access(p, m); }

static int o_read_small(const char *p, char *b, size_t sz, size_t *len)
{
    int fd = open(p, O_RDONLY);
    ssize_t n;

    if (fd < 0)
        return -errno;
    n = read(fd, b, sz - 1);
    close(fd);
    if (n < 0)
        return -errno;
    b[n] = '\0';
    if (len != NULL)
        *len = (size_t)n;
    return 0;
}

static int o_write_small(const char *p, const char *b, size_t len)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ssize_t n;

    if (fd < 0)
        return -errno;
    n = write(fd, b, len);
    close(fd);
    return n == (ssize_t)len ? 0 : -EIO;
}

static const l2s_rt_ops OPS = {
    o_lstat, o_symlink, o_rename, o_unlink,
    o_readlink, o_access, o_read_small, o_write_small
};

/* ------------------------------------------------------------------ */
/* 沙箱                                                               */
/* ------------------------------------------------------------------ */

static char g_dir[512];

static void sandbox_make(const char *tag)
{
    snprintf(g_dir, sizeof(g_dir), "./.l2s-entry-%s-%ld", tag, (long)getpid());
    (void)rmdir(g_dir);
    if (mkdir(g_dir, 0700) != 0) {
        printf("   （无法创建沙箱 %s，跳过）\n", g_dir);
        g_dir[0] = '\0';
    }
}

static void sandbox_drop(void)
{
    char cmd[600];

    if (g_dir[0] == '\0')
        return;
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_dir);
    if (system(cmd) != 0) {
        /* 清理失败不影响判据 */
    }
}

/* 建一个普通文件，返回其路径（写进 out）。 */
static void make_file(const char *name, char *out, size_t outsz,
                      const char *content)
{
    char path[600];
    int fd;

    snprintf(path, sizeof(path), "%s/%s", g_dir, name);
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, content, strlen(content));
        (void)w;
        close(fd);
    }
    snprintf(out, outsz, "%s", path);
}

/* ================================================================== */
/* T1. scheme 不变量：无论调用方传什么 scheme，伪装都必须生效            */
/* ================================================================== */

/*
 * 这条是本轮缺陷 ① 的**行为契约**。
 *
 * l2s-runtime 层只会写 PROOT 式名字（它全文件不引用 l2s_key16 /
 * l2s_meta_entry / L2S_PROROOT_META_DIR），所以调用方传 PROROOT 会让
 * "写出来的名字自己认不出来"，伪装静默失效。l2s_rt_init 必须把它归一化。
 *
 * 实测背景：同一份代码、同一颗 node，只换这一个字段 ——
 *     scheme=PROOT   -> nlink=2 isSymbolicLink=false
 *     scheme=PROROOT -> nlink=1 isSymbolicLink=true
 */
static void t_scheme_invariant(void)
{
    l2s_scheme schemes[2];
    int i;

    CASE("T1 scheme 不变量：传 PROROOT 也必须伪装成功");
    schemes[0] = L2S_SCHEME_PROROOT;
    schemes[1] = L2S_SCHEME_PROOT;

    for (i = 0; i < 2; i++) {
        l2s_config cfg = L2S_CONFIG_DEFAULT;
        struct stat st;
        char a[600], b[600], tag[32];

        snprintf(tag, sizeof(tag), "s%d", i);
        sandbox_make(tag);
        if (g_dir[0] == '\0')
            return;

        make_file("a", a, sizeof(a), "hi");
        snprintf(b, sizeof(b), "%s/b", g_dir);

        cfg.l2s_dir = NULL;
        cfg.scheme  = schemes[i];

        CHECK(l2s_rt_init(&OPS, &cfg) == 0, "l2s_rt_init 应成功");
        l2s_rt_reset_stats();

        CHECK(l2s_rt_link(a, b) == 0, "scheme=%d 时 link 应被接管",
              (int)schemes[i]);

        if (lstat(a, &st) == 0) {
            l2s_rt_patch_stat(&st, a);
            CHECK(st.st_nlink == 2,
                  "scheme=%d 的 st_nlink 应为 2，实得 %lu",
                  (int)schemes[i], (unsigned long)st.st_nlink);
            CHECK(!S_ISLNK(st.st_mode),
                  "scheme=%d 的 st_mode 不应带 S_IFLNK（mode=%07o）",
                  (int)schemes[i], (unsigned)st.st_mode);
        } else {
            CHECK(0, "lstat(%s) 失败", a);
        }

        /*
         * 计数器是"到底有没有真的 patch 过"的硬证据 ——
         * 只看 st_nlink 可能在"内核恰好返回 2"时误判为通过。
         */
        CHECK(l2s_rt_get_stats()->nlink_patched == 1,
              "scheme=%d 应有 1 次 nlink patch，实得 %lu",
              (int)schemes[i],
              l2s_rt_get_stats()->nlink_patched);

        l2s_rt_shutdown();
        sandbox_drop();
    }
}

/* ================================================================== */
/* T2. statx 补丁必须**连 S_IFLNK 一起抹掉**                            */
/* ================================================================== */

/*
 * 本轮缺陷 ③ 的直接契约。
 *
 * node/libuv 的 lstatSync() 走裸 syscall(291)，读的是 stx_mode。
 * 只补 stx_nlink 而留 S_IFLNK，客户一句 isSymbolicLink() 就得到 true。
 *
 * 官方 proroot 在同一位置返回 mode=0100600（已抹）；bxroot 修前是
 * mode=0120777（未抹）。
 */
static void t_statx_mode_masked(void)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    struct stat st;
    char a[600], b[600];
    unsigned int nlink = 0;
    unsigned int mask  = 0x00000200u;   /* STATX_NLINK */
    unsigned int mode;

    CASE("T2 statx 补丁抹掉 S_IFLNK，且 nlink 正确");
    sandbox_make("statx");
    if (g_dir[0] == '\0')
        return;

    make_file("a", a, sizeof(a), "hi");
    snprintf(b, sizeof(b), "%s/b", g_dir);

    cfg.l2s_dir = NULL;
    cfg.scheme  = L2S_SCHEME_PROOT;
    CHECK(l2s_rt_init(&OPS, &cfg) == 0, "l2s_rt_init 应成功");
    l2s_rt_reset_stats();
    CHECK(l2s_rt_link(a, b) == 0, "link 应被接管");

    CHECK(lstat(a, &st) == 0, "lstat 应成功");
    /* 模拟内核在 statx 里给出的原始值：磁盘上是符号链接。 */
    mode = (unsigned int)st.st_mode;
    CHECK((mode & S_IFMT) == S_IFLNK,
          "前置条件：磁盘上应是符号链接（mode=%07o）", mode);

    l2s_rt_patch_statx_full(&nlink, &mask, &mode, 0x00000200u, a);

    CHECK(nlink == 2, "statx 的 stx_nlink 应为 2，实得 %u", nlink);
    CHECK((mode & S_IFMT) == S_IFREG,
          "statx 的 stx_mode 应被抹成 S_IFREG，实得 %07o", mode);

    /*
     * 4 参数旧版必须**保持向后兼容**：只补 nlink、不动 mode。
     * preload.c 现有调用点按这个签名编译，改语义会让它静默变行为。
     */
    nlink = 0;
    mask  = 0x00000200u;
    mode  = (unsigned int)st.st_mode;
    l2s_rt_patch_statx(&nlink, &mask, 0x00000200u, a);
    CHECK(nlink == 2, "4 参数版仍应补 nlink（实得 %u）", nlink);
    CHECK((mode & S_IFMT) == S_IFLNK,
          "4 参数版应保持不动 mode（向后兼容，实得 %07o）", mode);

    l2s_rt_shutdown();
    sandbox_drop();
}

/* ================================================================== */
/* T3. 与 l2s 无关的路径不得被改动                                      */
/* ================================================================== */

static void t_no_false_positive(void)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    struct stat st, before;
    char plain[600];

    CASE("T3 普通文件/用户自己的符号链接原样放行");
    sandbox_make("fp");
    if (g_dir[0] == '\0')
        return;

    cfg.l2s_dir = NULL;
    cfg.scheme  = L2S_SCHEME_PROOT;
    CHECK(l2s_rt_init(&OPS, &cfg) == 0, "l2s_rt_init 应成功");
    l2s_rt_reset_stats();

    /* 1) 普通文件：nlink 必须保持 1，mode 保持 S_IFREG */
    make_file("plain", plain, sizeof(plain), "x");
    CHECK(lstat(plain, &before) == 0, "lstat(plain) 应成功");
    st = before;
    l2s_rt_patch_stat(&st, plain);
    CHECK(st.st_nlink == before.st_nlink,
          "普通文件 nlink 不应变（%lu -> %lu）",
          (unsigned long)before.st_nlink, (unsigned long)st.st_nlink);
    CHECK((st.st_mode & S_IFMT) == (before.st_mode & S_IFMT),
          "普通文件 mode 不应变");

    /* 2) 用户自己建的符号链接：不能被当成伪造链接 */
    {
        char real[600], lnk[600];

        make_file("real", real, sizeof(real), "y");
        snprintf(lnk, sizeof(lnk), "%s/mylink", g_dir);
        if (symlink(real, lnk) == 0) {
            CHECK(lstat(lnk, &before) == 0, "lstat(mylink) 应成功");
            st = before;
            l2s_rt_patch_stat(&st, lnk);
            CHECK(S_ISLNK(st.st_mode),
                  "用户自己的符号链接必须仍是 S_IFLNK（mode=%07o）",
                  (unsigned)st.st_mode);
        }
    }

    CHECK(l2s_rt_get_stats()->nlink_patched == 0,
          "与 l2s 无关的路径不应产生任何 nlink patch（实得 %lu）",
          l2s_rt_get_stats()->nlink_patched);

    l2s_rt_shutdown();
    sandbox_drop();
}

/* ================================================================== */
/* T4. l2s_rt_patch_stat 的 NULL / 未启用 防御                          */
/* ================================================================== */

static void t_defensive(void)
{
    struct stat st;

    CASE("T4 未 init 时透传，不崩溃");

    l2s_rt_shutdown();
    CHECK(l2s_rt_enabled() == 0, "shutdown 后应 disabled");

    memset(&st, 0, sizeof(st));
    l2s_rt_patch_stat(&st, "/tmp/whatever");
    CHECK(st.st_nlink == 0, "未启用时不应改动 st");

    /* NULL 参数：必须安全返回 */
    l2s_rt_patch_stat(NULL, "/tmp/x");
    l2s_rt_patch_stat(&st, NULL);
    l2s_rt_patch_statx(NULL, NULL, 0, "/tmp/x");
    l2s_rt_patch_statx_full(NULL, NULL, NULL, 0, "/tmp/x");
    CHECK(1, "NULL 参数不应崩溃");

    /* 未启用时 link/unlink/rename 一律透传 */
    CHECK(l2s_rt_link("/tmp/a", "/tmp/b") == L2S_RT_PASSTHRU,
          "未启用时 link 应透传");
    CHECK(l2s_rt_unlink("/tmp/a") == L2S_RT_PASSTHRU,
          "未启用时 unlink 应透传");
    CHECK(l2s_rt_rename("/tmp/a", "/tmp/b") == L2S_RT_PASSTHRU,
          "未启用时 rename 应透传");
}

/* ================================================================== */

int main(void)
{
    printf("== l2s stat 伪装：多入口契约测试 ==\n\n");

    t_scheme_invariant();
    t_statx_mode_masked();
    t_no_false_positive();
    t_defensive();

    printf("\n----------------------------------------\n");
    printf("通过 %d 项，失败 %d 项\n", g_pass, g_fail);
    if (g_fail != 0) {
        printf("RESULT: FAIL\n");
        return 1;
    }
    printf("RESULT: PASS\n");
    return 0;
}
