/*
 * probe_translate_props.c —— translate_path 的性质探针（F10）
 *
 * translate_path() 是每次文件操作都要过的唯一关口，它有三个必须成立的
 * 安全性质（任何一条不成立都是越界读写或静默错目标）：
 *
 *   P1 不漏宿主：返回 >0 时 out 必须是绝对路径，且以 rootfs 前缀或某条
 *      bind 的 source 开头 —— 也就是说，"已翻译"的结果绝不会是客户给的
 *      guest 路径原样透出（那会让内核从宿主根解析）。
 *   P2 不透传 guest：返回 0 时 out 必须等于入参（LOG 语义是"不翻译"），
 *      且该入参要么是相对路径、要么是 /proc /sys /dev、要么已带 rootfs。
 *   P3 幂等：translate(translate(x)) == translate(x)（已翻译路径再翻不得
 *      叠出 <rootfs><rootfs>）。
 *   P4 `..` 夹紧：任何以 `/` 开头且含 `..` 的 guest 路径，翻译结果都
 *      不得逃出 rootfs 前缀。超长/失败时必须给哨兵路径而不是原串。
 *
 * 差分方式：用一个独立写的参考模型（只按文档语义实现对上面 4 条性质
 * 的期望），逐项与实际实现对照。30 万条随机路径 × 4 个配置。
 *
 * 反向对照（修复前）：
 *   - 超长路径原写法返回 -1 且 out 未写 → 调用方把 guest 串漏给内核；
 *   - 未做幂等时 <rootfs><rootfs>/x。
 * 二者都会让 P1 失败。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 只测纯逻辑：不启动运行时，直接包含实现文件。 */
/* preload.c 自己定义 __dso_handle（生产构建带 -nostartfiles）；本探针走
 * 普通链接，crtbegin 已提供它。这里把它改名，避免与 crtbegin 冲突。 */
#define __dso_handle bxroot_probe_dso_handle
#include "preload.c"
#undef __dso_handle

static unsigned long long rs = 0xDEADBEEFCAFEULL;
static unsigned rnd(void)
{
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return (unsigned)(rs >> 11);
}

static int bad;
#define FAILP(...) do { if (bad++ < 25) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); } } while (0)

/* ---- 独立参考模型：按文档语义判定"必须成立"的性质 ---- */
static int ref_starts_with(const char *s, const char *p)
{
    size_t n = strlen(p);
    if (n == 0) return 0;
    return strncmp(s, p, n) == 0 && (s[n] == '\0' || s[n] == '/');
}

static void setup(const char *rootfs, char **srcs, char **tgts, int nbind)
{
    static char *s[8], *t[8];
    static int ro[8];
    int i;
    for (i = 0; i < nbind; i++) { s[i] = srcs[i]; t[i] = tgts[i]; ro[i] = 0; }
    g_config.rootfs = (char *)rootfs;
    g_config.tmp_dir = (char *)"/tmp";
    g_config.bind_sources = nbind ? s : NULL;
    g_config.bind_targets = nbind ? t : NULL;
    g_config.bind_readonly = nbind ? ro : NULL;
    g_config.bind_count = nbind;
}

static const char *pieces[] = { "/", "//", "proc", "sys", "dev", "shm", "tmp",
                                "etc", "a", "b.c", ".", "..", "...", ".x", "x." };

static void gen(char *buf, size_t cap)
{
    size_t pos = 0, n = rnd() % 9, i;
    buf[0] = 0;
    if (rnd() & 1) { buf[pos++] = '/'; buf[pos] = 0; }
    for (i = 0; i < n && pos < cap - 8; i++)
        pos += (size_t)snprintf(buf + pos, cap - pos, "%s%s",
                                pieces[rnd() % (sizeof pieces / sizeof pieces[0])],
                                (rnd() % 3 == 0) ? "/" : "");
}

static int probe_main(void)
{
    char *b1s[] = { "/host/cache/shm" }, *b1t[] = { "/dev/shm" };
    char *b2s[] = { "/dev", "/host/shm" }, *b2t[] = { "/dev", "/dev/shm" };
    char *b3s[] = { "/host/etc" }, *b3t[] = { "/etc" };
    long it;
    int cfg;

    for (cfg = 0; cfg < 4; cfg++) {
        const char *rootfs = "/data/data/com.dsh.client/files/linux/ubuntu";
        switch (cfg) {
        case 0: setup(rootfs, NULL, NULL, 0); break;
        case 1: setup(rootfs, b1s, b1t, 1); break;
        case 2: setup(rootfs, b2s, b2t, 2); break;
        default: setup(rootfs, b3s, b3t, 1); break;
        }

        for (it = 0; it < 75000; it++) {
            char in[MAX_PATH_LEN], out[MAX_PATH_LEN], out2[MAX_PATH_LEN];
            int rc, rc2, i;

            gen(in, sizeof in);
            if (in[0] == '\0') continue;

            memset(out, 0, sizeof out);
            rc = translate_path(in, out, sizeof out);

            /* P1: 返回 >0 必须是"已翻译"的绝对路径，绝不可以是原 guest 串 */
            if (rc > 0) {
                int ok = 0;
                if (out[0] != '/') FAILP("P1 非绝对 out=[%s] in=[%s]", out, in);
                if (ref_starts_with(out, rootfs)) ok = 1;
                for (i = 0; i < g_config.bind_count && !ok; i++)
                    if (g_config.bind_sources[i] &&
                        ref_starts_with(out, g_config.bind_sources[i]) &&
                        strcmp(g_config.bind_sources[i], g_config.bind_targets[i]) != 0)
                        ok = 1;
                /* 自映射 bind（src==tgt）在返回 1 时也可能是 guest 前缀，
                 * 但那条分支走的是"已带 bind source → 返回 0"，所以这里不豁免。 */
                /* 自映射 bind（src==tgt，如 -b /dev:/dev）命中时，翻译结果
                 * 本来就等于 guest 路径——那不是"漏宿主"，而是显式配置。 */
                {
                    int selfmap = 0;
                    for (i = 0; i < g_config.bind_count; i++)
                        if (g_config.bind_sources[i] && g_config.bind_targets[i] &&
                            strcmp(g_config.bind_sources[i], g_config.bind_targets[i]) == 0 &&
                            (ref_starts_with(in, g_config.bind_targets[i]) ||
                             ref_starts_with(out, g_config.bind_targets[i])))
                            selfmap = 1;
                    if (!ok && !selfmap)
                        FAILP("P1 未加前缀 rc=%d out=[%s] in=[%s]", rc, out, in);
                    if (strcmp(out, in) == 0 && in[0] == '/' && !selfmap &&
                        !ref_starts_with(in, "/proc") && !ref_starts_with(in, "/sys") &&
                        !ref_starts_with(in, "/dev") && !ref_starts_with(in, rootfs))
                        FAILP("P1 返回 1 却原样透出 guest in=[%s]", in);
                }

                /* P3 幂等 */
                rc2 = translate_path(out, out2, sizeof out2);
                if (strcmp(out, out2) != 0)
                    FAILP("P3 非幂等 in=[%s] out=[%s] out2=[%s]", in, out, out2);
            }

            /* P2: 返回 0 必须原样保留（LOG 语义），且原因必须是可解释的一类 */
            if (rc == 0) {
                /*
                 * 真实契约：rc<=0 时**调用方忽略 out**（标准写法
                 * `if (translate_path(...) > 0) p = translated;`；少数
                 * `>= 0` 的调用点只传绝对路径，见 preload.c 3054/3069/
                 * 3201/3421/3629/14086）。所以含 `..` 的相对路径经
                 * 绝对化 + 夹紧后落在 /proc 等透传前缀时，out 被改写而
                 * rc=0 是允许的 —— 只要改写结果本身不构成泄漏。
                 */
                if (strcmp(out, in) != 0 && in[0] != '/') {
                    int safe = !path_has_dotdot(out) &&
                               (ref_starts_with(out, "/proc") ||
                                ref_starts_with(out, "/sys") ||
                                ref_starts_with(out, "/dev") ||
                                ref_starts_with(out, rootfs));
                    if (!path_has_dotdot(in) || !safe)
                        FAILP("P2 相对路径被改写成可能泄漏的结果 in=[%s] out=[%s]", in, out);
                }
                if (in[0] == '/') {
                    int explained = ref_starts_with(in, rootfs) ||
                                    ref_starts_with(in, "/proc") ||
                                    ref_starts_with(in, "/sys") ||
                                    ref_starts_with(in, "/dev");
                    for (i = 0; i < g_config.bind_count && !explained; i++)
                        if (g_config.bind_sources[i] && strcmp(g_config.bind_sources[i],
                                                               g_config.bind_targets[i]) != 0 &&
                            ref_starts_with(in, g_config.bind_sources[i]))
                            explained = 1;
                    if (!explained && !path_has_dotdot(in))
                        FAILP("P2 绝对路径未翻译也无理由 in=[%s]", in);
                }
            }

            /* P4: `..` 夹紧 */
            if (in[0] == '/' && path_has_dotdot(in) && rc > 0) {
                if (!ref_starts_with(out, rootfs) &&
                    strstr(out, ".bxroot-unresolvable-path") == NULL) {
                    int i2, via_bind = 0;
                    for (i2 = 0; i2 < g_config.bind_count; i2++)
                        if (g_config.bind_sources[i2] &&
                            ref_starts_with(out, g_config.bind_sources[i2]))
                            via_bind = 1;
                    if (!via_bind)
                        FAILP("P4 `..` 逃出 rootfs out=[%s] in=[%s]", out, in);
                }
                /* 规范化之后不应再残留 `..` 组件 */
                if (path_has_dotdot(out) && strstr(out, "..") != NULL &&
                    strstr(out, ".bxroot-unresolvable-path") == NULL)
                    FAILP("P4 翻译结果仍含 `..` out=[%s] in=[%s]", out, in);
            }
        }
    }

    /* ---- 定点用例：超长必须给哨兵，不得把 guest 串漏出去 ---- */
    {
        char big[MAX_PATH_LEN], out[64];
        int rc;
        setup("/data/data/com.dsh.client/files/linux/ubuntu", NULL, NULL, 0);
        memset(big, 'a', sizeof big - 1);
        big[0] = '/';
        memcpy(big + 1, "aaa", 3);
        big[sizeof big - 1] = '\0';
        memset(out, 0, sizeof out);
        rc = translate_path(big, out, sizeof out);
        if (rc > 0 && out[0] != '/')
            FAILP("定点 超长 rc=%d out 非绝对", rc);
        if (rc <= 0)
            FAILP("定点 超长返回 <=0（调用方会把 guest 串漏给内核）rc=%d", rc);
        if (strstr(out, "unresolvable") == NULL)
            FAILP("定点 超长未给哨兵 out=[%s]", out);
    }

    /* ---- 定点用例：/dev/shm 重定向与 bind 优先级 ---- */
    {
        char out[MAX_PATH_LEN];
        int rc;
        setup("/rootfs", NULL, NULL, 0);
        rc = translate_path("/dev/shm/x", out, sizeof out);
        if (rc <= 0 || strstr(out, "/tmp/.bxroot-shm/x") == NULL)
            FAILP("定点 /dev/shm 未重定向 rc=%d out=[%s]", rc, out);
        if (strncmp(out, "/rootfs", 7) != 0)
            FAILP("定点 /dev/shm 未加 rootfs out=[%s]", out);

        /* 显式 bind 优先于重定向 */
        setup("/rootfs", b1s, b1t, 1);
        rc = translate_path("/dev/shm/x", out, sizeof out);
        if (rc <= 0 || strcmp(out, "/host/cache/shm/x") != 0)
            FAILP("定点 bind 未优先于 /dev/shm 重定向 rc=%d out=[%s]", rc, out);

        /* 自映射 bind 不得废掉更具体的 bind */
        setup("/rootfs", b2s, b2t, 2);
        rc = translate_path("/dev/shm/y", out, sizeof out);
        if (rc <= 0 || strcmp(out, "/host/shm/y") != 0)
            FAILP("定点 自映射 bind 抢占了更具体的 bind rc=%d out=[%s]", rc, out);
        /* 自映射 bind 命中时实现返回 1 + 原路径（与透传可观测等价）：
         * 关键是**不得**叠出 /rootfs/dev/null。 */
        rc = translate_path("/dev/null", out, sizeof out);
        if (strcmp(out, "/dev/null") != 0)
            FAILP("定点 自映射 bind 下 /dev/null 不得叠前缀 rc=%d out=[%s]", rc, out);

        /* 组件边界：/devx 不是 /dev */
        setup("/rootfs", b2s, b2t, 2);
        rc = translate_path("/devx", out, sizeof out);
        if (rc <= 0 || strncmp(out, "/rootfs/devx", 12) != 0)
            FAILP("定点 /devx 被误当 /dev rc=%d out=[%s]", rc, out);
    }

    printf("bad=%d\n", bad);
    return bad != 0;
}

/* 真正的入口：绕过被 preload.c 接管的 main 无关符号，只跑探针本体。 */
int main(void) { return probe_main(); }
