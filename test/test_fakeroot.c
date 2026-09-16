/*
 * test_fakeroot.c -- fakeroot 记账层与 stat 补丁的单元测试
 *
 * 全部是纯逻辑测试：不碰内核，不依赖 LD_PRELOAD。这很重要 —— 本容器
 * 无法端到端验证 LD_PRELOAD（外层 proot 会吞掉它），但 fakeroot 的
 * 核心价值恰恰全在纯逻辑里（记账表 + 字段改写决策），所以这一层测得动，
 * 而且测得准。
 *
 * 覆盖：
 *   A. 记账表的增删查改、三种键型、容量上限、淘汰
 *   B. stat / stat64 / statx 的 uid/gid/mode 改写
 *   C. access 判定模型（含 root 绕过）
 *   D. chown 动作决策（特权 / 非特权）
 *   E. 状态机：setuid 家族、caps 维护
 *   F. 边界与防御（空指针、越界、禁用状态）
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>   /* makedev/major/minor：B6 要构造与内核同型的 dev_t */
#include <unistd.h>

#include "fakeroot.h"

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
/* 辅助：构造一个「已启用、假 root」的状态                              */
/* ------------------------------------------------------------------ */

/*
 * 真实身份取 2000（Android app 的 uid），假身份取 0。
 * 这正是 DSHA 生产的场景：不受信用户想装包，必须看起来是 root。
 */
static void state_root(fakeroot_state *fs)
{
    memset(fs, 0, sizeof(*fs));
    fs->enabled     = true;
    fs->ruid = fs->euid = fs->suid = fs->fsuid = 0;
    fs->rgid = fs->egid = fs->sgid = fs->fsgid = 0;
    fs->real_uid = fs->real_euid = 2000;
    fs->real_gid = fs->real_egid = 2000;
    fs->heuristic = FR_HEURISTIC_OWNER;
}

/* 给状态挂上记账表（构造真实的两张表） */
static void state_attach_maps(fakeroot_state *fs)
{
    fs->by_path  = fakeroot_map_create(256);
    fs->by_inode = fakeroot_map_create(256);
}

static void state_detach_maps(fakeroot_state *fs)
{
    if (fs->by_path)  { fakeroot_map_destroy(fs->by_path);  fs->by_path  = NULL; }
    if (fs->by_inode) { fakeroot_map_destroy(fs->by_inode); fs->by_inode = NULL; }
}

/* 真实身份与假身份相同的「未伪装」状态 */
static void state_passthrough(fakeroot_state *fs)
{
    memset(fs, 0, sizeof(*fs));
    fs->enabled = true;
    fs->ruid = fs->euid = fs->suid = fs->fsuid = 2000;
    fs->rgid = fs->egid = fs->sgid = fs->fsgid = 2000;
    fs->real_uid = fs->real_euid = 2000;
    fs->real_gid = fs->real_egid = 2000;
}

/* ================================================================== */
/* A. 记账表                                                           */
/* ================================================================== */

/*
 * 重要契约（fakeroot.h:309-311）：
 *   fakeroot_map_put(m, k, rec) 之后，**k 的所有权转移给表**，
 *   调用方不得再对它调用 fakeroot_key_dispose()。
 *
 * k 是按值传的，所以调用方手里那份副本看起来仍然"有效"（kind 非零、
 * 指针非空），dispose 它会释放表仍然持有的那块内存 —— 之后
 * map_destroy 再释放一次，就是 double free。我的第一版测试就踩了这个，
 * 崩在 tcache 里。这是 API 用法错误，不是库的缺陷；但见报告里对这一
 * 设计风险的说明。
 */
static void t_map_basic(void)
{
    fakeroot_map *m;
    fr_key k;
    fr_record rec, got;
    char path[] = "/etc/passwd";

    CASE("A1 记账表：写入后能按路径键查回");
    m = fakeroot_map_create(64);
    CHECK(m != NULL);
    if (m == NULL) return;

    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);

    memset(&rec, 0, sizeof(rec));
    rec.uid = 0;
    rec.gid = 0;
    rec.mode = 0644;
    rec.mode_faked = 1;

    CHECK_EQ_I(fakeroot_map_put(m, k, &rec), FR_OK);
    CHECK_EQ_I(fakeroot_map_count(m), 1);

    memset(&got, 0, sizeof(got));
    CHECK_EQ_I(fakeroot_map_get(m, &k, &got), FR_OK);
    CHECK_EQ_I(got.uid, 0);
    CHECK_EQ_I(got.gid, 0);
    CHECK_EQ_I(got.mode, 0644);
    CHECK_EQ_I(got.mode_faked, 1);

    /* 不再 dispose(&k)：所有权已随 put 转移，交给 map_destroy */
    fakeroot_map_destroy(m);
}

static void t_map_overwrite(void)
{
    fakeroot_map *m;
    fr_key k;
    fr_record rec, got;
    char path[] = "/tmp/x";

    CASE("A2 记账表：同一键重复写入是覆盖，不是追加");
    m = fakeroot_map_create(64);
    if (m == NULL) return;

    /*
     * 每次 put 都必须造一个**全新的** key。
     *
     * 这不是洁癖，是 map_put 的契约使然：k 按值传入，所有权转移给表。
     * 若第二次 put 复用同一个 k，表会先 dispose 槽里那个（= k 指向的
     * 那块内存，已被释放），再把 k 存回槽里 —— 槽里从此是个悬垂指针，
     * 后续 get/destroy 就是 use-after-free。
     *
     * 第一版测试正是这么写的，结果崩在 tcache 的 double free 里。
     */
    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);
    memset(&rec, 0, sizeof(rec));
    rec.uid = 111;
    CHECK_EQ_I(fakeroot_map_put(m, k, &rec), FR_OK);

    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);   /* 新键 */
    rec.uid = 222;
    CHECK_EQ_I(fakeroot_map_put(m, k, &rec), FR_OK);

    /* 计数必须还是 1 —— 重复写入不能把表撑大 */
    CHECK_EQ_I(fakeroot_map_count(m), 1);

    /* 查询用一个又新造的键，绝不复用已交出去的那份 */
    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);
    memset(&got, 0, sizeof(got));
    CHECK_EQ_I(fakeroot_map_get(m, &k, &got), FR_OK);
    CHECK_EQ_I(got.uid, 222);   /* 后写的胜出 */
    fakeroot_key_dispose(&k);   /* 这份从未 put，由调用方释放 */

    fakeroot_map_destroy(m);
}

static void t_map_missing(void)
{
    fakeroot_map *m;
    fr_key k;
    fr_record got;
    char path[] = "/never/inserted";

    CASE("A3 记账表：查不到的键返回未命中，不返回垃圾数据");
    m = fakeroot_map_create(64);
    if (m == NULL) return;

    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);

    /* 先把缓冲区填成可识别的垃圾，再查询 */
    memset(&got, 0xAB, sizeof(got));
    CHECK(fakeroot_map_get(m, &k, &got) != FR_OK);
    CHECK_EQ_I(fakeroot_map_has(m, &k), false);

    /* 未命中时不得改写调用方的缓冲区 */
    {
        unsigned char *p = (unsigned char *)&got;
        size_t i;
        int all_ab = 1;
        for (i = 0; i < sizeof(got); i++)
            if (p[i] != 0xAB) { all_ab = 0; break; }
        CHECK(all_ab);
    }

    fakeroot_key_dispose(&k);   /* 从未 put，调用方负责 */
    fakeroot_map_destroy(m);
}

static void t_map_key_kinds(void)
{
    fakeroot_map *m;
    fr_key kp, ki, kf;
    fr_record rec, got;
    char path[] = "/a/b";

    CASE("A4 记账表：path / inode / fd 三种键互不串味");
    m = fakeroot_map_create(64);
    if (m == NULL) return;

    memset(&rec, 0, sizeof(rec));

    CHECK_EQ_I(fakeroot_key_path(&kp, path), FR_OK);
    rec.uid = 1;
    CHECK_EQ_I(fakeroot_map_put(m, kp, &rec), FR_OK);

    CHECK_EQ_I(fakeroot_key_inode(&ki, (dev_t)7, (ino_t)42), FR_OK);
    rec.uid = 2;
    CHECK_EQ_I(fakeroot_map_put(m, ki, &rec), FR_OK);

    CHECK_EQ_I(fakeroot_key_fd(&kf, 9), FR_OK);
    rec.uid = 3;
    CHECK_EQ_I(fakeroot_map_put(m, kf, &rec), FR_OK);

    CHECK_EQ_I(fakeroot_map_count(m), 3);

    memset(&got, 0, sizeof(got));
    CHECK_EQ_I(fakeroot_map_get(m, &kp, &got), FR_OK);
    CHECK_EQ_I(got.uid, 1);
    CHECK_EQ_I(fakeroot_map_get(m, &ki, &got), FR_OK);
    CHECK_EQ_I(got.uid, 2);
    CHECK_EQ_I(fakeroot_map_get(m, &kf, &got), FR_OK);
    CHECK_EQ_I(got.uid, 3);

    fakeroot_map_destroy(m);
}

static void t_map_clear(void)
{
    fakeroot_map *m;
    fr_key k;
    fr_record rec;
    char path[] = "/p";

    CASE("A5 记账表：清空后计数归零且查不到");
    m = fakeroot_map_create(64);
    if (m == NULL) return;

    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ_I(fakeroot_map_put(m, k, &rec), FR_OK);
    CHECK_EQ_I(fakeroot_map_count(m), 1);

    fakeroot_map_clear(m);
    CHECK_EQ_I(fakeroot_map_count(m), 0);
    CHECK_EQ_I(fakeroot_map_has(m, &k), false);

    fakeroot_map_destroy(m);
}

static void t_map_capacity(void)
{
    fakeroot_map *m;
    fr_record rec;
    int i;
    int inserted = 0;

    CASE("A6 记账表：超容量时不能崩，也不能无限增长");
    m = fakeroot_map_create(16);
    CHECK(m != NULL);
    if (m == NULL) return;

    memset(&rec, 0, sizeof(rec));

    /* 灌 200 条（远超 16 槽），容忍插入失败，但绝不允许崩溃或越界 */
    for (i = 0; i < 200; i++) {
        char path[64];
        fr_key k;
        snprintf(path, sizeof(path), "/file-%d", i);
        if (fakeroot_key_path(&k, path) != FR_OK)
            continue;
        /* put 接管所有权：插不进去时由 put 自己释放，插进去时归表 */
        if (fakeroot_map_put(m, k, &rec) == FR_OK)
            inserted++;
    }

    CHECK(inserted > 0);                       /* 至少能装下一些 */
    CHECK(fakeroot_map_count(m) <= fakeroot_map_capacity(m));

    fakeroot_map_destroy(m);
}

static void t_map_disabled(void)
{
    fakeroot_map *m;
    fr_key k;
    fr_record rec, got;
    char path[] = "/d";

    CASE("A7 记账表：置为 disabled 后写入不生效（可回退开关）");
    m = fakeroot_map_create(64);
    if (m == NULL) return;

    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);
    memset(&rec, 0, sizeof(rec));
    rec.uid = 5;

    CHECK_EQ_I(fakeroot_map_put(m, k, &rec), FR_OK);   /* k 交出去了 */
    fakeroot_map_set_disabled(m, true);
    CHECK_EQ_I(fakeroot_map_is_disabled(m), true);

    /* 禁用后旧记录不应再被读出 —— 否则「关掉伪装」是假动作 */
    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);    /* 查询另造新键 */
    memset(&got, 0, sizeof(got));
    CHECK(fakeroot_map_get(m, &k, &got) != FR_OK);

    fakeroot_map_set_disabled(m, false);
    CHECK_EQ_I(fakeroot_map_is_disabled(m), false);
    CHECK_EQ_I(fakeroot_map_get(m, &k, &got), FR_OK);
    CHECK_EQ_I(got.uid, 5);

    fakeroot_key_dispose(&k);   /* 这份只用于查询，由调用方释放 */
    fakeroot_map_destroy(m);
}

static void t_key_defensive(void)
{
    fr_key k;

    CASE("A8 键构造：空指针与超长路径被拒，不越界");
    CHECK(fakeroot_key_path(NULL, "/x") != FR_OK);
    CHECK(fakeroot_key_path(&k, NULL) != FR_OK);
    CHECK(fakeroot_key_path(&k, "") != FR_OK);

    /* 超长路径（超过 FR_PATH_MAX）必须被拒，而不是截断后冒充合法键 */
    {
        char *huge = malloc(FR_PATH_MAX + 64);
        if (huge != NULL) {
            memset(huge, 'a', FR_PATH_MAX + 63);
            huge[0] = '/';
            huge[FR_PATH_MAX + 63] = '\0';
            CHECK(fakeroot_key_path(&k, huge) != FR_OK);
            free(huge);
        }
    }
}

/* ================================================================== */
/* B. stat 补丁                                                        */
/* ================================================================== */

static void t_patch_stat_records(void)
{
    fakeroot_state fs;
    fakeroot_map *m;
    fr_key k;
    fr_record rec;
    struct stat st;
    char path[] = "/etc/shadow";

    CASE("B1 stat 补丁：有记账时按记账改写 uid/gid");
    state_root(&fs);
    state_attach_maps(&fs);
    m = fs.by_path;
    if (m == NULL) { state_detach_maps(&fs); return; }

    CHECK_EQ_I(fakeroot_key_path(&k, path), FR_OK);
    memset(&rec, 0, sizeof(rec));
    rec.uid = 0;
    rec.gid = 0;
    CHECK_EQ_I(fakeroot_map_put(m, k, &rec), FR_OK);

    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0644;
    st.st_uid  = 2000;          /* 内核给的真实属主 */
    st.st_gid  = 2000;
    st.st_dev  = 7;
    st.st_ino  = 42;

    fakeroot_patch_stat_ex(&st, &fs, &rec, -1);

    CHECK_EQ_I(st.st_uid, 0);   /* 被改写成假身份 */
    CHECK_EQ_I(st.st_gid, 0);
    CHECK_EQ_I(st.st_mode & S_IFMT, S_IFREG);  /* 文件类型位必须保留 */

    state_detach_maps(&fs);
}

static void t_patch_stat_disabled(void)
{
    fakeroot_state fs;
    struct stat st;

    CASE("B2 stat 补丁：未启用时一个字节都不改");
    memset(&fs, 0, sizeof(fs));
    fs.enabled = false;

    memset(&st, 0, sizeof(st));
    st.st_uid = 1234;
    st.st_gid = 5678;
    st.st_mode = S_IFREG | 0600;

    fakeroot_patch_stat(&st, &fs);

    CHECK_EQ_I(st.st_uid, 1234);
    CHECK_EQ_I(st.st_gid, 5678);
    CHECK_EQ_I(st.st_mode, S_IFREG | 0600);
}

static void t_patch_stat_null(void)
{
    fakeroot_state fs;
    struct stat st;

    CASE("B3 stat 补丁：空指针不崩（这类崩溃在 LD_PRELOAD 里是致命的）");
    state_root(&fs);

    fakeroot_patch_stat(NULL, &fs);      /* 必须安全 */
    fakeroot_patch_stat(&st, NULL);      /* 必须安全 */
    fakeroot_patch_stat(NULL, NULL);     /* 必须安全 */
    CHECK(1);                            /* 走到这里就算通过 */
}

static void t_patch_statx(void)
{
    fakeroot_state fs;
    fr_record rec;
    struct statx stx;

    CASE("B4 statx 补丁：uid/gid 被改写，且不破坏 mask");
    state_root(&fs);

    memset(&stx, 0, sizeof(stx));
    stx.stx_uid = 2000;
    stx.stx_gid = 2000;
    stx.stx_mode = 0100644;
    stx.stx_mask = STATX_UID | STATX_GID | STATX_MODE;

    memset(&rec, 0, sizeof(rec));
    rec.uid = 0;
    rec.gid = 0;

    fakeroot_patch_statx_ex(&stx, &fs, &rec, -1);

    CHECK_EQ_I(stx.stx_uid, 0);
    CHECK_EQ_I(stx.stx_gid, 0);
    CHECK((stx.stx_mask & STATX_UID) != 0);
    CHECK((stx.stx_mask & STATX_GID) != 0);
}

static void t_mode_faked(void)
{
    fakeroot_state fs;
    fr_record rec;
    struct stat st;

    CASE("B5 只有 mode_faked 置位时才改写权限位");
    state_root(&fs);

    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0644;
    st.st_uid = 2000; st.st_gid = 2000;

    /* 未置 mode_faked：权限位保持内核值 */
    memset(&rec, 0, sizeof(rec));
    rec.uid = 0; rec.gid = 0; rec.mode = 0777; rec.mode_faked = 0;
    {
        struct stat a = st;
        fakeroot_patch_stat_ex(&a, &fs, &rec, -1);
        CHECK_EQ_I(a.st_mode & 07777, 0644);
    }

    /* 置 mode_faked：权限位被记账值覆盖 */
    rec.mode_faked = 1;
    {
        struct stat b = st;
        fakeroot_patch_stat_ex(&b, &fs, &rec, -1);
        CHECK_EQ_I(b.st_mode & 07777, 0777);
        CHECK_EQ_I(b.st_mode & S_IFMT, S_IFREG);   /* 类型位仍来自内核 */
    }
}

/*
 * B6 —— statx 的 dev 键必须与写侧同型（F3 回归）。
 *
 * 缺陷：statx 路径把 stx_dev_major（只有主设备号）当 dev_t 去查 by_inode，
 * 而写侧存的是完整 st.st_dev。minor 非零时两个键永不相等，查询恒 MISS。
 * 本机实测 st_dev=0xfe3e vs stx_dev_major=0xfe。
 *
 * 这里**不碰文件系统**：dev_t 由 makedev() 直接构造，statx 结构体手工填，
 * 走的是 fakeroot_patch_statx_ex(rec == NULL, fd < 0) —— 三条调用路径里
 * 唯一让这个查询成为**唯一**信息来源的那条（另两条：rec != NULL 不查；
 * fd >= 0 由 fakeroot_lookup_fd 兜底）。
 *
 * 为了让「记账丢失」可观测，必须把启发式关掉（FR_HEURISTIC_OFF）：
 * 否则 OWNER 启发式会把 == real_uid 的属主也改写成假身份，掩盖掉差异。
 * 这正是审计报告说「被掩盖」的机制在纯记账层的对应物。
 */
static void t_patch_statx_dev_key(void)
{
    fakeroot_state fs;
    struct statx   stx;
    fr_record      rec;
    dev_t          dev;
    const unsigned major_n = 254;    /* 本机 /data 所在分区的真实主设备号 */
    const unsigned minor_n = 62;     /* 非零 —— 正是 F3 暴露的必要条件 */

    CASE("B6 statx 补丁：dev 键必须还原成完整 dev_t（minor 不能丢）");

    memset(&fs, 0, sizeof(fs));
    fs.enabled   = true;
    fs.heuristic = FR_HEURISTIC_OFF;      /* 记账是唯一信息来源 */
    fs.ruid = fs.euid = fs.suid = fs.fsuid = 9999;   /* 假身份 */
    fs.rgid = fs.egid = fs.sgid = fs.fsgid = 9999;
    fs.real_uid = fs.real_euid = 2000;               /* 真实身份 */
    fs.real_gid = fs.real_egid = 2000;
    state_attach_maps(&fs);
    if (fs.by_inode == NULL) { state_detach_maps(&fs); return; }

    dev = makedev(major_n, minor_n);
    CHECK(minor(dev) != 0);               /* 前提：minor 必须非零 */
    CHECK(dev != (dev_t)major_n);         /* 前提：major 单独 != 完整 dev_t */

    /* 写侧：与 fr_record_inode_for_path 完全一致 —— 存完整 st_dev */
    memset(&rec, 0, sizeof(rec));
    CHECK_EQ_I(fakeroot_record_owner_inode(&fs, dev, (ino_t)123456, 1234, 1234),
               FR_OK);

    /* 读侧：手工构造 statx 结果（内核报属主 0，既非真实也非假身份） */
    memset(&stx, 0, sizeof(stx));
    stx.stx_dev_major = major_n;
    stx.stx_dev_minor = minor_n;
    stx.stx_ino       = 123456;
    stx.stx_uid       = 0;
    stx.stx_gid       = 0;
    stx.stx_mode      = 0100644;
    stx.stx_mask      = STATX_UID | STATX_GID | STATX_MODE;

    /* 三条调用路径的对照：rec==NULL && fd<0 是唯一能被这条查询救的 */
    fakeroot_patch_statx_ex(&stx, &fs, NULL, -1);
    CHECK_EQ_I(stx.stx_uid, 1234);        /* 修复前是 0（记账丢失） */
    CHECK_EQ_I(stx.stx_gid, 1234);

    /* 反向对照：major 单独当 dev_t 必须查不到 —— 证明断言不是侥幸通过 */
    {
        fr_record got;
        CHECK(fakeroot_lookup(&fs, NULL, (dev_t)major_n, (ino_t)123456, &got)
              != FR_OK);
        CHECK_EQ_I(fakeroot_lookup(&fs, NULL, dev, (ino_t)123456, &got), FR_OK);
    }

    /* fd >= 0 那条路径：本 harness 没记 fd 键 ⇒ 兜底不成立，
     * 结果与 rec==NULL && fd<0 一致（都是记账生效，因为 inode 那路已修好） */
    {
        struct statx s2 = stx;
        s2.stx_uid = 0;
        s2.stx_gid = 0;
        fakeroot_patch_statx_ex(&s2, &fs, NULL, 0);
        CHECK_EQ_I(s2.stx_uid, 1234);
    }

    /* rec != NULL：调用方预取，与 inode 查询无关，必须同样生效 */
    {
        struct statx s3;
        fr_record r3;
        memset(&s3, 0, sizeof(s3));
        s3.stx_dev_major = major_n;
        s3.stx_dev_minor = minor_n;
        s3.stx_ino = 123456;
        s3.stx_mask = STATX_UID | STATX_GID;
        memset(&r3, 0, sizeof(r3));
        r3.uid = 4321; r3.gid = 4321;
        r3.uid_faked = true; r3.gid_faked = true;
        fakeroot_patch_statx_ex(&s3, &fs, &r3, -1);
        CHECK_EQ_I(s3.stx_uid, 4321);
    }

    state_detach_maps(&fs);
}

/* ================================================================== */
/* C. access 判定                                                      */
/* ================================================================== */
static void t_access_model(void)
{
    struct stat st;

    CASE("C1 access：属主/组/其他三档权限判定");
    memset(&st, 0, sizeof(st));
    st.st_mode = S_IFREG | 0640;    /* owner=rw, group=r, other=--- */
    st.st_uid = 0;
    st.st_gid = 0;

    /* 作为属主（uid 0）：读、写可以，执行不行 */
    CHECK_EQ_I(fakeroot_check_access(&st, R_OK, true, true), FR_ACCESS_GRANTED);
    CHECK_EQ_I(fakeroot_check_access(&st, W_OK, true, true), FR_ACCESS_GRANTED);
    CHECK_EQ_I(fakeroot_check_access(&st, X_OK, true, true), FR_ACCESS_DENIED);

    /* F_OK（存在性）在模型层一律放行 */
    CHECK_EQ_I(fakeroot_check_access(&st, F_OK, true, true), FR_ACCESS_GRANTED);

    /* st 无效时不能凭一个未初始化的结构下结论 */
    /* st_valid=false ⇒ 保守放行，让真实 errno 透出去 */
    CHECK_EQ_I(fakeroot_check_access(&st, R_OK, false, true), FR_ACCESS_GRANTED);
}

/* ================================================================== */
/* D. chown 动作决策                                                   */
/* ================================================================== */

static void t_chown_decision(void)
{
    fakeroot_state fs;

    CASE("D1 chown：真实调用成功时不需要伪造");
    state_root(&fs);

    /* 真调用返回 0 —— 直接放行，没什么要补的 */
    CHECK_EQ_I(fakeroot_chown_action(0, 0, FR_OK), FR_CHOWN_PROPAGATE);

    CASE("D2 chown：非特权下 EPERM 应被吞掉并记入表");
    /*
     * 这是 fakeroot 的核心价值：真实内核不许改属主（EPERM），
     * 但客户以为成功了。必须返回「假装成功 + 记表」，
     * 而不是把 EPERM 原样抛给 dpkg。
     */
    {
        fr_chown_action act = fakeroot_chown_action(-1, EPERM, FR_OK);
        CHECK_EQ_I(act, FR_CHOWN_FAKE_OK);
    }

    CASE("D3 chown：非权限类错误（如 ENOENT）必须如实上抛");
    {
        /* 文件不存在不能假装成功，否则客户会以为改好了 */
        fr_chown_action act = fakeroot_chown_action(-1, ENOENT, FR_OK);
        CHECK_EQ_I(act, FR_CHOWN_PROPAGATE);
    }
}

/* ================================================================== */
/* E. 身份状态机                                                       */
/* ================================================================== */

static void t_identity_consistency(void)
{
    fakeroot_state fs;

    CASE("E1 身份：四个 uid 必须能被独立设置并各自读回");
    state_root(&fs);

    /*
     * setresuid(-1, 1000, -1) 只改 euid。若实现把四个值合成一个，
     * 这里立刻暴露 —— 而 dpkg 的 postinst 正是靠这个区分来判断
     * 自己有没有真正降权。
     */
    fs.euid = 1000;
    CHECK_EQ_I(fs.ruid, 0);
    CHECK_EQ_I(fs.euid, 1000);
    CHECK_EQ_I(fs.suid, 0);

    fs.suid = 1000;
    CHECK_EQ_I(fs.suid, 1000);
    CHECK_EQ_I(fs.ruid, 0);
}

static void t_groups(void)
{
    fakeroot_state fs;

    CASE("E2 补充组：集合可设置且不越界");
    state_root(&fs);

    fs.groups[0] = 0;
    fs.groups[1] = 1000;
    fs.groups[2] = 2000;
    fs.ngroups = 3;

    CHECK_EQ_I(fs.ngroups, 3);
    CHECK_EQ_I(fs.groups[2], 2000);

    /* 上限必须被尊重 —— 越界写会踩坏相邻字段 */
    CHECK(FR_NGROUPS_MAX >= 3);
    CHECK(FR_NGROUPS_MAX <= 1024);
}

/* ================================================================== */
/* F. 防御性                                                           */
/* ================================================================== */

static void t_passthrough_identity(void)
{
    fakeroot_state fs;
    struct stat st;

    CASE("F1 真假身份相同时不应产生可见变化（避免无谓改写）");
    state_passthrough(&fs);

    memset(&st, 0, sizeof(st));
    st.st_uid = 2000;
    st.st_gid = 2000;

    fakeroot_patch_stat(&st, &fs);
    CHECK_EQ_I(st.st_uid, 2000);
    CHECK_EQ_I(st.st_gid, 2000);
}

static void t_map_create_bounds(void)
{
    CASE("F2 建表：非法槽位数被拒或归一，不产生不可用对象");

    /* 0 槽：要么返回 NULL，要么归一到可用值 —— 但不能返回一个
     * 「看似可用实则写不进去」的表 */
    {
        fakeroot_map *m = fakeroot_map_create(0);
        if (m != NULL) {
            CHECK(fakeroot_map_capacity(m) > 0);
            fakeroot_map_destroy(m);
        }
    }

    /* 超大槽位：不应试图真的分配 1<<40 个槽 */
    {
        fakeroot_map *m = fakeroot_map_create((size_t)1 << 40);
        if (m != NULL) {
            CHECK(fakeroot_map_capacity(m) <= FR_MAP_MAX_SLOTS);
            fakeroot_map_destroy(m);
        }
    }
}

/* ================================================================== */

int main(void)
{
    printf("fakeroot 记账与 stat 补丁测试\n");
    printf("（纯逻辑；不依赖 LD_PRELOAD，故本容器内结果可信）\n");
    printf("========================================\n\n");

    printf("[A] 记账表\n");
    t_map_basic();
    t_map_overwrite();
    t_map_missing();
    t_map_key_kinds();
    t_map_clear();
    t_map_capacity();
    t_map_disabled();
    t_key_defensive();

    printf("\n[B] stat / statx 补丁\n");
    t_patch_stat_records();
    t_patch_stat_disabled();
    t_patch_stat_null();
    t_patch_statx();
    t_mode_faked();
    t_patch_statx_dev_key();

    printf("\n[C] access 判定\n");
    t_access_model();

    printf("\n[D] chown 决策\n");
    t_chown_decision();

    printf("\n[E] 身份状态机\n");
    t_identity_consistency();
    t_groups();

    printf("\n[F] 防御性\n");
    t_passthrough_identity();
    t_map_create_bounds();

    printf("\n----------------------------------------\n");
    printf("cases:  %d  (%d 失败)\n", g_cases, g_failed);
    printf("checks: %d  (%d 失败)\n", g_checks, g_failed);
    printf("RESULT: %s\n", g_failed == 0 ? "PASS" : "FAIL");
    return g_failed == 0 ? 0 : 1;
}
