/* =====================================================================
 * probe_nss_edge.c —— getpwnam/getpwnam_r/getgrnam/getgrnam_r
 *                      「/etc/passwd、/etc/group 直解回退」边界探针
 * =====================================================================
 *
 * 配套 runner：test/RUN_NSS_EDGE.sh（在 bxroot 容器内端到端执行，
 * 走真实的直解代码路径；本探针不做任何文件操作，只做查询与判据）。
 *
 * 环境变量
 *   EDGE_CASES=1,10    只跑指定用例（1 起始编号；缺省全跑）。
 *                      runner 按「文件组」分批换 /etc/passwd、/etc/group，
 *                      每批只跑属于该批的用例，见 runner 的组表。
 *   EDGE_EXPECT_DIRECT=1
 *                      声明本进程由 bxroot runtime 驱动（直解路径预期生效）。
 *                      对照侧（官方 runtime）**不要**设置：官方走真实 NSS，
 *                      「预期失败」类用例在对照侧只记 skip 不判失败。
 *
 * 输出契约（runner 依赖，勿改格式）
 *   每例一行：[ok] T01 ... / [FAIL] T01 ... / [skip] T01 ...
 *   末行    ：probe EDGE: ok=<n> fail=<n> skip=<n> mode=<...>
 *   退出码  ：0 = 无 FAIL（允许 skip）；1 = 有 FAIL
 *
 * 判据设计要点
 *   - 「预期失败」类用例（T02/T03/T08）在直解侧必须是 NULL；若对照侧的
 *     真实 NSS 意外命中了非法行，那是 glibc 的行为差异，记 skip 不判
 *     失败（本测试钉的是 bxroot 直解解析器，不是 glibc）。
 *   - T01 在两侧都是硬判据：官方侧真实 NSS 应能查到，bxroot 侧直解应能
 *     查到，谁查不到谁坏 —— 这是本测试的「环境对照锚点」。
 */

#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_ok, g_fail, g_skip;
static int g_direct;   /* EDGE_EXPECT_DIRECT=1（bxroot 直解侧） */
static int g_case[16]; /* EDGE_CASES 解析结果 */
static int g_ncase;
static int g_all = 1;

static int case_on(int id)
{
    int i;
    if (g_all)
        return 1;
    for (i = 0; i < g_ncase; i++)
        if (g_case[i] == id)
            return 1;
    return 0;
}

static void ok_(int id, const char *what, const char *detail)
{
    g_ok++;
    printf("[ok] T%02d %s %s\n", id, what, detail);
}

static void fail_(int id, const char *what, const char *detail)
{
    g_fail++;
    printf("[FAIL] T%02d %s %s\n", id, what, detail);
}

static void skip_(int id, const char *what, const char *detail)
{
    g_skip++;
    printf("[skip] T%02d %s %s\n", id, what, detail);
}

/* 「预期缺席」类用例：直解侧必须 NULL；对照侧意外命中只跳过。 */
static void want_absent(int id, int present, const char *what)
{
    if (!present) {
        ok_(id, what, "返回 NULL，未崩溃");
        return;
    }
    if (!g_direct)
        skip_(id, what, "对照侧真实 NSS 意外命中（本判据只针对直解路径）");
    else
        fail_(id, what, "直解路径错误地命中了非法行");
}

/* ---------------------------------------------------------------------
 * T01 正常行：root:x:0:0:root:/root:/bin/sh → uid=0，字段逐个核对
 * ------------------------------------------------------------------ */
static void t01(void)
{
    struct passwd *pw = getpwnam("root");
    struct passwd st, *res = NULL;
    char buf[512];
    int rc = getpwnam_r("root", &st, buf, sizeof buf, &res);

    if (pw == NULL) { fail_(1, "getpwnam(root)", "返回 NULL"); return; }
    if (pw->pw_uid != 0) { fail_(1, "getpwnam(root)", "uid!=0"); return; }
    if (pw->pw_name == NULL || strcmp(pw->pw_name, "root") != 0) {
        fail_(1, "getpwnam(root)", "pw_name 不符"); return;
    }
    if (pw->pw_dir == NULL || strcmp(pw->pw_dir, "/root") != 0) {
        fail_(1, "getpwnam(root)", "pw_dir 不符"); return;
    }
    if (pw->pw_shell == NULL || strcmp(pw->pw_shell, "/bin/sh") != 0) {
        fail_(1, "getpwnam(root)", "pw_shell 不符"); return;
    }
    if (rc != 0 || res == NULL || res->pw_uid != 0) {
        fail_(1, "getpwnam_r(root)", "rc/result 异常"); return;
    }
    ok_(1, "getpwnam(root)", "uid=0 dir=/root shell=/bin/sh，_r 同步正确");
}

/* ---------------------------------------------------------------------
 * T02 缺字段：bad:x:1:2（只有 3 个字段）→ 整行跳过，不崩溃
 * ------------------------------------------------------------------ */
static void t02(void)
{
    struct passwd *pw = getpwnam("bad");
    struct passwd st, *res = (void *)1;
    char buf[256];
    int rc = getpwnam_r("bad", &st, buf, sizeof buf, &res);
    int present = (pw != NULL) || (rc == 0 && res != NULL);

    want_absent(2, present, "缺字段行(bad:x:1:2) 应整行跳过");
}

/* ---------------------------------------------------------------------
 * T03 全空行文件（只有空行）→ 查任意名返回 NULL
 * ------------------------------------------------------------------ */
static void t03(void)
{
    struct passwd *pw = getpwnam("x");
    struct group *gr = getgrnam("x");
    int present = (pw != NULL) || (gr != NULL);

    want_absent(3, present, "空行文件 查任意名 应 NULL");
}

/* ---------------------------------------------------------------------
 * T04 超长行：passwd 里一行 990+ 字节（fgets(512) 会切块），group 里
 * 一行 >1024 字节（fgets(1024) 会切块）→ 不越界不崩溃，
 * 且长行之后普通行的查询完全不受影响。
 * ------------------------------------------------------------------ */
static void t04(void)
{
    char needle[1000];
    struct passwd *pw, *pw2;
    struct passwd st, *res = NULL;
    struct group *gr2;
    char buf[4096];
    int rc, bad = 0;

    memset(needle, 'a', sizeof needle - 1);
    needle[sizeof needle - 1] = '\0';

    /* 长名条目：命中与否都不许崩溃；命中则字段指针必须可用 */
    pw = getpwnam(needle);
    if (pw != NULL && (pw->pw_name == NULL || pw->pw_dir == NULL ||
                       pw->pw_shell == NULL))
        bad = 1;

    /* 长行之后，root 仍必须查得到（切块解析不能污染后续行） */
    pw2 = getpwnam("root");
    if (pw2 == NULL || pw2->pw_uid != 0)
        bad = 1;

    rc = getpwnam_r("root", &st, buf, sizeof buf, &res);
    if (rc != 0 || res == NULL || res->pw_uid != 0)
        bad = 1;

    /* 组文件的 >1024 字节长行同样只许被跳过 */
    gr2 = getgrnam("root");
    if (gr2 == NULL || gr2->gr_gid != 0)
        bad = 1;

    if (!bad)
        ok_(4, "超长行(>1024 字节)", "未越界未崩溃，后续查询不受影响");
    else
        fail_(4, "超长行(>1024 字节)", "长行处理异常（见上方判据组合）");
}

/* ---------------------------------------------------------------------
 * T05 uid/gid 非数字：bad:x:abc:def:... → atoi=0 语义或整行拒绝，不崩溃
 * ------------------------------------------------------------------ */
static void t05(void)
{
    struct passwd *pw = getpwnam("badnum");
    struct passwd st, *res = NULL;
    char buf[256];
    int rc = getpwnam_r("badnum", &st, buf, sizeof buf, &res);

    if (pw == NULL && !(rc == 0 && res != NULL)) {
        ok_(5, "uid/gid 非数字", "该行被拒绝（NULL）—— 可接受");
        return;
    }
    if (pw != NULL && pw->pw_uid == 0 && pw->pw_gid == 0 &&
        pw->pw_name != NULL && strcmp(pw->pw_name, "badnum") == 0) {
        ok_(5, "uid/gid 非数字", "atoi=0 语义，未崩溃");
        return;
    }
    if (rc == 0 && res != NULL && res->pw_uid == 0 && res->pw_gid == 0) {
        ok_(5, "uid/gid 非数字", "_r 版 atoi=0 语义，未崩溃");
        return;
    }
    fail_(5, "uid/gid 非数字", "返回了非零垃圾 uid/gid 或字段损坏");
}

/* ---------------------------------------------------------------------
 * T06 多成员组：g:x:1:m1,m2,m3,m4,m5 → gr_mem 恰 5 个且内容正确
 * ------------------------------------------------------------------ */
static void t06(void)
{
    static const char *want[5] = { "m1", "m2", "m3", "m4", "m5" };
    struct group *gr = getgrnam("g");
    int n = 0, i, bad = 0;

    if (gr == NULL) { fail_(6, "多成员组(g)", "返回 NULL"); return; }
    if (gr->gr_gid != 1)
        bad = 1;
    if (gr->gr_mem != NULL)
        while (gr->gr_mem[n] != NULL)
            n++;
    if (n != 5)
        bad = 1;
    for (i = 0; i < 5; i++)
        if (gr->gr_mem == NULL || gr->gr_mem[i] == NULL ||
            strcmp(gr->gr_mem[i], want[i]) != 0)
            bad = 1;

    if (!bad)
        ok_(6, "多成员组(g)", "gr_mem 5 个成员，gid=1，内容逐一相符");
    else
        fail_(6, "多成员组(g)", "成员数/内容/gid 不符");
}

/* ---------------------------------------------------------------------
 * T07 空成员列表：empty:x:1: → gr_mem[0]==NULL
 * ------------------------------------------------------------------ */
static void t07(void)
{
    struct group *gr = getgrnam("empty");

    if (gr == NULL) { fail_(7, "空成员组(empty)", "返回 NULL"); return; }
    if (gr->gr_mem == NULL) {
        fail_(7, "空成员组(empty)", "gr_mem 本身为 NULL（应为 NULL 结尾数组）");
        return;
    }
    if (gr->gr_mem[0] != NULL) {
        fail_(7, "空成员组(empty)", "gr_mem[0] 非 NULL（空成员被解析成幽灵成员）");
        return;
    }
    if (gr->gr_gid != 1) { fail_(7, "空成员组(empty)", "gid 不符"); return; }
    ok_(7, "空成员组(empty)", "gr_mem[0]==NULL");
}

/* ---------------------------------------------------------------------
 * T08 /etc/passwd 不存在 → NULL，不崩溃（fopen 失败路径）
 * ------------------------------------------------------------------ */
static void t08(void)
{
    struct passwd *pw = getpwnam("root");
    struct passwd st, *res = (void *)1;
    char buf[256];
    int rc = getpwnam_r("root", &st, buf, sizeof buf, &res);
    int present = (pw != NULL) || (rc == 0 && res != NULL);

    want_absent(8, present, "/etc/passwd 不存在 应 NULL");
}

/* ---------------------------------------------------------------------
 * T09 连续 100 次：四族（getpwnam/_r/getgrnam/_r）结果全部一致
 * ------------------------------------------------------------------ */
static void t09(void)
{
    struct passwd *pw;
    struct group *gr;
    struct passwd st, *res = NULL;
    struct group gt, *gres = NULL;
    char b1[512], b2[512];
    int i, bad = 0;

    for (i = 0; i < 100; i++) {
        pw = getpwnam("root");
        if (pw == NULL || pw->pw_uid != 0 || pw->pw_name == NULL ||
            strcmp(pw->pw_name, "root") != 0) { bad = 1; break; }
        gr = getgrnam("g");
        if (gr == NULL || gr->gr_gid != 1) { bad = 1; break; }
        res = NULL;
        if (getpwnam_r("root", &st, b1, sizeof b1, &res) != 0 ||
            res == NULL || res->pw_uid != 0) { bad = 1; break; }
        gres = NULL;
        if (getgrnam_r("g", &gt, b2, sizeof b2, &gres) != 0 ||
            gres == NULL || gres->gr_gid != 1) { bad = 1; break; }
    }
    if (!bad)
        ok_(9, "连续 100 次", "四族结果全部一致");
    else
        fail_(9, "连续 100 次", "结果漂移或中途失败");
}

/* ---------------------------------------------------------------------
 * T10 ERANGE：buf 只有 8 字节 → 两族都必须 ERANGE 且 *result==NULL
 * （缓冲区 8 字节连 "root\0" 加 "x\0" 都勉强，gecos 必然放不下）
 * ------------------------------------------------------------------ */
static void t10(void)
{
    struct passwd st, *res = NULL;
    struct group gt, *gres = NULL;
    char tiny[8], detail[96];
    int rc1, rc2, bad = 0;

    rc1 = getpwnam_r("root", &st, tiny, sizeof tiny, &res);
    if (rc1 != ERANGE || res != NULL)
        bad = 1;

    rc2 = getgrnam_r("g", &gt, tiny, sizeof tiny, &gres);
    if (rc2 != ERANGE || gres != NULL)
        bad = 1;

    if (!bad) {
        ok_(10, "ERANGE(buf=8)", "passwd/group 两族均 ERANGE 且 result=NULL");
    } else {
        snprintf(detail, sizeof detail,
                 "passwd rc=%d(期望%d) group rc=%d(期望%d)",
                 rc1, ERANGE, rc2, ERANGE);
        fail_(10, "ERANGE(buf=8)", detail);
    }
}

int main(void)
{
    const char *e;
    int rc;

    e = getenv("EDGE_EXPECT_DIRECT");
    g_direct = (e != NULL && e[0] == '1');

    e = getenv("EDGE_CASES");
    if (e != NULL && e[0] != '\0') {
        char *p = (char *)e;
        g_all = 0;
        while (*p != '\0' && g_ncase < 16) {
            g_case[g_ncase++] = (int)strtol(p, &p, 10);
            if (*p == ',')
                p++;
        }
    }

    printf("probe EDGE: start mode=%s cases=%s\n",
           g_direct ? "bxroot-direct" : "official-nss",
           (e != NULL && e[0] != '\0') ? e : "all");

    if (case_on(1))  t01();
    if (case_on(2))  t02();
    if (case_on(3))  t03();
    if (case_on(4))  t04();
    if (case_on(5))  t05();
    if (case_on(6))  t06();
    if (case_on(7))  t07();
    if (case_on(8))  t08();
    if (case_on(9))  t09();
    if (case_on(10)) t10();

    printf("probe EDGE: ok=%d fail=%d skip=%d mode=%s\n",
           g_ok, g_fail, g_skip, g_direct ? "bxroot-direct" : "official-nss");
    fflush(stdout);

    rc = (g_fail > 0) ? 1 : 0;
    return rc;
}
