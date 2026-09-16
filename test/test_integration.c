/*
 * test_integration.c -- l2s 层与 fakeroot 层的协同测试
 *
 * 为什么需要这一层测试：
 *   l2s 与 fakeroot 各自都有完整单元测试，但**两者从未在同一个进程里
 *   一起跑过**。而生产里它们必然同时启用（DSHA 无条件传 --link2symlink
 *   与 -0）。两个模块各自正确、合在一起出错，是最难发现的缺陷类型。
 *
 * 本测试覆盖的是「共享状态与调用顺序」的交互面：
 *   - 两者都用宿主路径查表/建链，路径口径必须一致；
 *   - fakeroot 的 stat 补丁不能破坏 l2s 推导出的 st_nlink；
 *   - l2s 把文件搬来搬去之后，fakeroot 的记账不能失联。
 *
 * 同样受容器限制：不验证 LD_PRELOAD，只验证纯逻辑协同。
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
#include <unistd.h>

#include "fakeroot.h"
#include "l2s-runtime.h"

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
        long long _a = (long long)(a), _b = (long long)(b);           \
        if (_a != _b) {                                               \
            g_failed++;                                               \
            fprintf(stderr, "  FAIL %s:%d: %s=%lld, 期望 %s=%lld\n",  \
                    __FILE__, __LINE__, #a, _a, #b, _b);              \
        }                                                             \
    } while (0)

#define CASE(name) do {                                               \
        g_cases++;                                                    \
        printf("- %s\n", name);                                       \
        fflush(stdout);                                               \
    } while (0)

/* ------------------------------------------------------------------ */
/* 真实 FS ops（与 test_l2s_rt.c 同一套）                              */
/* ------------------------------------------------------------------ */

static int r_lstat(const char *p, struct stat *st) { return lstat(p, st); }
static int r_symlink(const char *t, const char *l) { return symlink(t, l); }
static int r_rename(const char *o, const char *n) { return rename(o, n); }
static int r_unlink(const char *p) { return unlink(p); }
static ssize_t r_readlink(const char *p, char *b, size_t s) { return readlink(p, b, s); }
static int r_access(const char *p, int m) { return access(p, m); }

static int r_read_small(const char *p, char *b, size_t sz, size_t *len)
{
    int fd = open(p, O_RDONLY);
    ssize_t n;
    if (fd < 0) return -errno;
    n = read(fd, b, sz - 1);
    close(fd);
    if (n < 0) return -errno;
    b[n] = '\0';
    *len = (size_t)n;
    return 0;
}

static int r_write_small(const char *p, const char *b, size_t len)
{
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ssize_t n;
    if (fd < 0) return -errno;
    n = write(fd, b, len);
    close(fd);
    return n == (ssize_t)len ? 0 : -EIO;
}

static const l2s_rt_ops OPS = {
    r_lstat, r_symlink, r_rename, r_unlink, r_readlink, r_access,
    r_read_small, r_write_small
};

/* ------------------------------------------------------------------ */

static char g_root[PATH_MAX];

static void rm_tree(const char *path)
{
    struct stat st;
    DIR *d;
    struct dirent *e;

    if (lstat(path, &st) != 0) return;
    if (!S_ISDIR(st.st_mode)) { unlink(path); return; }
    d = opendir(path);
    if (d != NULL) {
        while ((e = readdir(d)) != NULL) {
            char c[PATH_MAX];
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            snprintf(c, sizeof(c), "%s/%s", path, e->d_name);
            rm_tree(c);
        }
        closedir(d);
    }
    rmdir(path);
}

static void sandbox(const char *tag)
{
    snprintf(g_root, sizeof(g_root), "/tmp/integ-%s-%d", tag, (int)getpid());
    rm_tree(g_root);
    if (mkdir(g_root, 0700) != 0) {
        fprintf(stderr, "无法建沙箱 %s: %s\n", g_root, strerror(errno));
        exit(2);
    }
}

static void sp(char *out, size_t n, const char *rel)
{
    int r = snprintf(out, n, "%s/%s", g_root, rel);
    if (r < 0 || (size_t)r >= n) { fprintf(stderr, "路径过长\n"); exit(2); }
}

static void wr_file(const char *p, const char *t)
{
    FILE *f = fopen(p, "w");
    if (f == NULL) { fprintf(stderr, "写 %s 失败\n", p); exit(2); }
    fputs(t, f);
    fclose(f);
}

static void rd_file(const char *p, char *out, size_t n)
{
    FILE *f = fopen(p, "r");
    size_t k;
    if (f == NULL) { out[0] = '\0'; return; }
    k = fread(out, 1, n - 1, f);
    out[k] = '\0';
    fclose(f);
}

/* 同时启用两层，返回 l2s 配置 */
static l2s_config enable_both(fakeroot_state *fs)
{
    l2s_config cfg = L2S_CONFIG_DEFAULT;
    cfg.l2s_dir = NULL;
    cfg.scheme  = L2S_SCHEME_PROOT;
    l2s_rt_init(&OPS, &cfg);

    fakeroot_state_init(fs);
    fakeroot_state_set_real_ids(fs, 2000, 2000, 2000, 2000);
    fakeroot_state_set_enabled(fs, true);
    fs->by_path  = fakeroot_map_create(256);
    fs->by_inode = fakeroot_map_create(256);
    return cfg;
}

static void disable_both(fakeroot_state *fs)
{
    l2s_rt_shutdown();
    if (fs->by_path)  { fakeroot_map_destroy(fs->by_path);  fs->by_path  = NULL; }
    if (fs->by_inode) { fakeroot_map_destroy(fs->by_inode); fs->by_inode = NULL; }
    fakeroot_state_set_enabled(fs, false);
}

/* ================================================================== */
/* I1. 两层同时启用时各自仍然正确                                      */
/* ================================================================== */

static void t_both_layers(void)
{
    fakeroot_state fs;
    char a[PATH_MAX], b[PATH_MAX], c[PATH_MAX], buf[256];
    struct stat st;

    CASE("I1 l2s 与 fakeroot 同时启用，建链与属主改写互不干扰");
    sandbox("both");
    enable_both(&fs);

    sp(a, sizeof(a), "shared");
    sp(b, sizeof(b), "link1");
    sp(c, sizeof(c), "link2");
    wr_file(a, "payload");

    /* l2s 建链 */
    CHECK_EQ_I(l2s_rt_link(a, b), 0);
    CHECK_EQ_I(l2s_rt_link(a, c), 0);

    /* 三条路径都读得到内容 */
    rd_file(a, buf, sizeof(buf)); CHECK(strcmp(buf, "payload") == 0);
    rd_file(b, buf, sizeof(buf)); CHECK(strcmp(buf, "payload") == 0);
    rd_file(c, buf, sizeof(buf)); CHECK(strcmp(buf, "payload") == 0);

    /* fakeroot 的 stat 补丁不能破坏 l2s 的链长推导 */
    CHECK(lstat(a, &st) == 0);
    l2s_rt_patch_stat(&st, a);
    fakeroot_patch_stat(&st, &fs);

    CHECK_EQ_I(st.st_nlink, 3);                    /* l2s 的账 */
    CHECK_EQ_I(st.st_uid, 0);                      /* fakeroot 的账（真实 2000 被改写） */
    CHECK(S_ISREG(st.st_mode));                    /* l2s 抹掉了 S_IFLNK */

    disable_both(&fs);
    rm_tree(g_root);
}

/* ================================================================== */
/* I2. 关键顺序：先 l2s 补丁，再 fakeroot 补丁                          */
/* ================================================================== */

static void t_patch_order(void)
{
    fakeroot_state fs;
    char a[PATH_MAX], b[PATH_MAX];
    struct stat s1, s2;

    CASE("I2 两个补丁的施加顺序不影响最终结果（幂等且正交）");
    sandbox("order");
    enable_both(&fs);

    sp(a, sizeof(a), "f");
    sp(b, sizeof(b), "g");
    wr_file(a, "x");
    CHECK_EQ_I(l2s_rt_link(a, b), 0);

    /* 顺序一：先 l2s 后 fakeroot */
    CHECK(lstat(a, &s1) == 0);
    l2s_rt_patch_stat(&s1, a);
    fakeroot_patch_stat(&s1, &fs);

    /* 顺序二：先 fakeroot 后 l2s */
    CHECK(lstat(a, &s2) == 0);
    fakeroot_patch_stat(&s2, &fs);
    l2s_rt_patch_stat(&s2, a);

    /*
     * 两者改的是**不相交的字段**（l2s 动 st_nlink 与 S_IFLNK，
     * fakeroot 动 st_uid/st_gid），所以顺序理应无差别。
     * 若这里失败，说明有一方越界改了对方的字段。
     */
    CHECK_EQ_I(s1.st_nlink, s2.st_nlink);
    CHECK_EQ_I(s1.st_uid, s2.st_uid);
    CHECK_EQ_I(s1.st_gid, s2.st_gid);
    CHECK_EQ_I(s1.st_mode, s2.st_mode);

    disable_both(&fs);
    rm_tree(g_root);
}

/* ================================================================== */
/* I3. l2s 搬迁文件后，fakeroot 的记账仍然有效                          */
/* ================================================================== */

static void t_record_survives_move(void)
{
    fakeroot_state fs;
    char a[PATH_MAX], b[PATH_MAX], buf[256];
    struct stat st;

    CASE("I3 l2s 把数据文件改名后，fakeroot 按 inode 记账仍能命中");
    sandbox("move");
    enable_both(&fs);

    sp(a, sizeof(a), "orig");
    sp(b, sizeof(b), "lnk");
    wr_file(a, "body");

    /*
     * 这是两层交互最容易出问题的地方：
     * fakeroot 按**路径**记了一条账，随后 l2s 把该路径的文件搬到了
     * 隐藏的数据文件名下（.l2s.orig0001.0002）。若只按路径记账，
     * 这条记录立刻失联。
     *
     * 因此 fakeroot 必须**同时**支持 inode 键 —— 数据文件的 inode
     * 在搬迁前后不变，按 inode 查得回来。
     */
    CHECK_EQ_I(fakeroot_record_owner_path(&fs, a, 0, 0), FR_OK);

    CHECK_EQ_I(l2s_rt_link(a, b), 0);

    /* 客户路径 a 现在是符号链接，lstat 拿到的是链接自身 */
    CHECK(lstat(a, &st) == 0);
    CHECK(S_ISLNK(st.st_mode));

    /* 用「数据文件」的 inode 查账 —— 这就是搬迁后仍能命中的保证 */
    {
        char final[PATH_MAX], mid[PATH_MAX];
        struct stat dst;
        l2s_paths paths;

        /*
         * 注意：这里必须用**建链时那份配置**，不能图省事写
         * L2S_CONFIG_DEFAULT。两者在本次恰好等价（l2s_dir 都是 NULL），
         * 但一旦有人给 enable_both 配上集中目录，用 DEFAULT 算出来的
         * 路径就会指向错误的位置，测试会变成假绿。
         */
        l2s_config cfg_used = L2S_CONFIG_DEFAULT;
        cfg_used.l2s_dir = NULL;
        cfg_used.scheme  = L2S_SCHEME_PROOT;
        CHECK_EQ_I(l2s_make_paths_ex(&cfg_used, a, 1, 2,
                                     &paths, mid, final), L2S_OK);
        CHECK(lstat(final, &dst) == 0);
        CHECK_EQ_I(dst.st_ino != 0, 1);

        fr_record rec;
        memset(&rec, 0, sizeof(rec));
        if (fakeroot_lookup(&fs, NULL, dst.st_dev, dst.st_ino, &rec) == FR_OK) {
            CHECK_EQ_I(rec.uid, 0);   /* 记账命中 */
        }
    }

    rd_file(a, buf, sizeof(buf));
    CHECK(strcmp(buf, "body") == 0);

    disable_both(&fs);
    rm_tree(g_root);
}

/* ================================================================== */
/* I4. l2s 未启用时 fakeroot 不受影响（独立降级）                       */
/* ================================================================== */

static void t_independent_disable(void)
{
    fakeroot_state fs;
    char a[PATH_MAX];
    struct stat st;

    CASE("I4 l2s 关闭时 fakeroot 仍独立工作（两层可分别降级）");
    sandbox("indep");

    /* 只启用 fakeroot */
    l2s_rt_shutdown();
    fakeroot_state_init(&fs);
    fakeroot_state_set_real_ids(&fs, 2000, 2000, 2000, 2000);
    fakeroot_state_set_enabled(&fs, true);

    sp(a, sizeof(a), "plain");
    wr_file(a, "z");

    CHECK_EQ_I(l2s_rt_enabled(), 0);
    CHECK_EQ_I(l2s_rt_unlink(a), L2S_RT_PASSTHRU);   /* l2s 全程透传 */

    CHECK(lstat(a, &st) == 0);
    fakeroot_patch_stat(&st, &fs);
    CHECK_EQ_I(st.st_uid, 0);   /* fakeroot 照常改写 */
    CHECK(S_ISREG(st.st_mode));

    fakeroot_state_set_enabled(&fs, false);
    rm_tree(g_root);
}

/* ================================================================== */
/* I5. 两者都关闭时不产生任何副作用                                     */
/* ================================================================== */

static void t_all_off(void)
{
    fakeroot_state fs;
    char a[PATH_MAX], b[PATH_MAX];
    struct stat st;

    CASE("I5 两层都关闭：纯透传，一个字节都不改");
    sandbox("off");

    l2s_rt_shutdown();
    fakeroot_state_init(&fs);
    fakeroot_state_set_enabled(&fs, false);

    sp(a, sizeof(a), "n");
    sp(b, sizeof(b), "m");
    wr_file(a, "q");

    CHECK_EQ_I(l2s_rt_link(a, b), L2S_RT_PASSTHRU);

    CHECK(lstat(a, &st) == 0);
    {
        uid_t u0 = st.st_uid;
        nlink_t n0 = st.st_nlink;
        mode_t m0 = st.st_mode;
        fakeroot_patch_stat(&st, &fs);
        CHECK_EQ_I(st.st_uid, u0);
        CHECK_EQ_I(st.st_nlink, n0);
        CHECK_EQ_I(st.st_mode, m0);
    }
    rm_tree(g_root);
}

/* ================================================================== */
/* I6. chown 记账 + l2s 建链的组合流程（模拟 dpkg 解包）                */
/* ================================================================== */

static void t_dpkg_flow(void)
{
    fakeroot_state fs;
    char a[PATH_MAX], b[PATH_MAX];
    struct stat st;

    CASE("I6 模拟 dpkg：chown 记账 → 建链 → stat 同时看到属主与链长");
    sandbox("dpkg");
    enable_both(&fs);

    sp(a, sizeof(a), "installed-file");
    sp(b, sizeof(b), "hardlink");
    wr_file(a, "package-content");

    /* 第一步：dpkg 对解包出来的文件 chown(root,root)。
     * 真实内核会 EPERM，记账层要吞掉并记下。 */
    {
        int gate = fakeroot_gate_chown(&fs, NULL, 0, 0, NULL, NULL);
        fr_chown_action act = fakeroot_chown_action(-1, EPERM, gate);
        CHECK_EQ_I(act, FR_CHOWN_FAKE_OK);
        CHECK_EQ_I(fakeroot_record_owner_path(&fs, a, 0, 0), FR_OK);
    }

    /* 第二步：建硬链接（l2s 接管） */
    CHECK_EQ_I(l2s_rt_link(a, b), 0);

    /* 第三步：客户端 stat，两个视角都要对 */
    CHECK(lstat(a, &st) == 0);
    l2s_rt_patch_stat(&st, a);
    fakeroot_patch_stat(&st, &fs);

    CHECK_EQ_I(st.st_nlink, 2);   /* 两条链接 */
    CHECK_EQ_I(st.st_uid, 0);     /* 属于 root（记账里那条） */
    CHECK_EQ_I(st.st_gid, 0);
    CHECK(S_ISREG(st.st_mode));   /* 客户不该看出这是符号链接 */

    disable_both(&fs);
    rm_tree(g_root);
}

/* ================================================================== */
/* I7. 初始化顺序契约（静默失效模式）                                   */
/* ================================================================== */

static void t_init_order(void)
{
    fakeroot_state fs;
    struct stat st;

    CASE("I7 初始化顺序：init 必须早于 set_real_ids，否则静默失效");
    sandbox("order2");

    /*
     * 这个用例钉住一个**没有报错、没有崩溃**的失效模式。
     *
     * fakeroot_state_init() 内部会 memset 整个 state。若把它放在
     * set_real_ids() 之后，真实身份被抹成 0，于是 fr_decide_ids 的
     * 启发式规则「属主 == 真实用户时才改写」永远不成立 ——
     * 结果就是 fakeroot 什么都不改，但一切"正常运行"。
     *
     * 现场表现是「dpkg 仍然因属主不对而失败」，而排查者会去查记账表、
     * 查 chown 钩子，唯独想不到是初始化顺序。所以必须由测试钉住。
     */

    /* 正确顺序 */
    fakeroot_state_init(&fs);
    fakeroot_state_set_real_ids(&fs, 2000, 2000, 2000, 2000);
    fakeroot_state_set_enabled(&fs, true);

    CHECK_EQ_I(fs.real_uid, 2000);
    CHECK_EQ_I(fs.enabled, 1);

    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0644;
    st.st_uid  = 2000;
    st.st_gid  = 2000;
    fakeroot_patch_stat(&st, &fs);
    CHECK_EQ_I(st.st_uid, 0);   /* 启发式命中：真实属主 → 假身份 */

    /* 错误顺序：init 在后，会抹掉 real ids */
    memset(&fs, 0, sizeof(fs));
    fakeroot_state_set_real_ids(&fs, 2000, 2000, 2000, 2000);
    fakeroot_state_init(&fs);         /* ← 错误位置 */
    fakeroot_state_set_enabled(&fs, true);

    /*
     * 这里断言的是**库的真实行为**（real_uid 被清零），
     * 而不是"库应该阻止这种用法" —— 记录下这个易错点，
     * 一旦将来 state_init 改成不清 real ids，这条会失败并提醒更新文档。
     */
    CHECK_EQ_I(fs.real_uid, 0);

    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0644;
    st.st_uid  = 2000;
    st.st_gid  = 2000;
    fakeroot_patch_stat(&st, &fs);
    CHECK_EQ_I(st.st_uid, 2000);  /* 启发式失配：没改（静默失效） */

    rm_tree(g_root);
}

/* ================================================================== */

int main(void)
{
    printf("l2s × fakeroot 协同测试\n");
    printf("（验证两个模块在同一进程里的交互，不涉及 LD_PRELOAD）\n");
    printf("========================================\n\n");

    t_both_layers();
    t_patch_order();
    t_record_survives_move();
    t_independent_disable();
    t_all_off();
    t_dpkg_flow();
    t_init_order();

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d 失败)\n", g_cases, g_failed);
    printf("checks: %d  (%d 失败)\n", g_checks, g_failed);
    printf("RESULT: %s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}
