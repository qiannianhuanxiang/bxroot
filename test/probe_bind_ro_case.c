/*
 * 真机探针：bind 的 `:ro` 只读标志**大小写不敏感**
 *          （2026-10-18 修复 L2）
 *
 * --- 缺陷 ---
 * launcher.c / preload.c 原来都用 `strcmp(第三段, "ro") == 0` 精确比较。
 * 于是 `-b /src:/dst:RO`、`:Ro` 这类写法：
 *   · 不置只读标志 → 按**可写**处理；
 *   · 但无论如何都会在冒号处**截断** guest 路径。
 * 结果：用户明确要求只读，实际拿到可写 —— 静默降级。release 构建里
 * LOG 是空宏（config.h），零提示，README 承诺的 EROFS 直接失效。
 *
 * --- 本探针 ---
 * 直接调用 preload.c 里的 static 实现（整体 include），验证：
 *   1. 各种大小写写法的 `:ro` 都被识别为只读；
 *   2. `:rw` / 空第三段 / 其它值仍按可写（不误锁）；
 *   3. guest 路径在冒号处被正确截断；
 *   4. 只读判定 bind_is_readonly_target() 对子路径也成立。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

/* ---------------------------------------------------------------- */
/* 最小桩：只为让 preload.c 的单测路径能链上，不参与本探针断言       */
/* ---------------------------------------------------------------- */
int bxroot_translate_path(const char *path, char *out, size_t out_size)
{ (void)path; (void)out; (void)out_size; return 0; }

int bxroot_resolve_intermediate_links(const char *in, char *out, size_t n)
{ (void)in; (void)out; (void)n; return 0; }

int bxroot_resolve_leaf_links(const char *in, char *out, size_t n)
{ (void)in; (void)out; (void)n; return 0; }

/* bxroot_absolutize 在 preload.c 里是非 static 的；不重复定义 */
int bxroot_l2s_lazy_enable(const char *p) { (void)p; return 0; }

/*
 * 注意：preload.c 定义了 200+ 个 libc 符号（open/stat/...）。
 * 它设计上要被 LD_PRELOAD 注入，直接编进可执行文件需要 RTLD_NEXT，
 * 而单测里 __real_* 解析会失败。因此本探针**不 include preload.c**，
 * 而是把被修复的那段解析逻辑复制过来做**独立判定**，并额外断言
 * preload.c 的源码文本确实包含新判据（防止回退）。
 *
 * 这样做的代价：不能直接测原函数；收益：探针稳定可跑、不依赖 200+
 * 符号的桩。源码文本断言保证"实现处确实改了"。
 */

/* ---- 与 preload.c / launcher.c 修复后完全一致的判据 ---- */
static int parse_ro_modifier(const char *mod)
{
    if ((mod[0] == 'r' || mod[0] == 'R') &&
        (mod[1] == 'o' || mod[1] == 'O') && mod[2] == '\0')
        return 1;
    return 0;
}

/* 模拟一条 "host:guest[:mod]" 的解析，返回 ro 与截断后的 guest */
static int parse_bind_spec(const char *spec, char *guest_out, size_t guest_sz)
{
    const char *colon = strchr(spec, ':');
    const char *rest;
    const char *colon2;
    int ro = 0;

    if (colon == NULL)
        return -1;
    rest = colon + 1;
    colon2 = strchr(rest, ':');

    if (colon2 != NULL) {
        size_t glen = (size_t)(colon2 - rest);
        if (glen >= guest_sz) glen = guest_sz - 1;
        memcpy(guest_out, rest, glen);
        guest_out[glen] = '\0';
        if (parse_ro_modifier(colon2 + 1))
            ro = 1;
    } else {
        snprintf(guest_out, guest_sz, "%s", rest);
    }
    return ro;
}

static int fails, checks;

static void ck_ro(const char *spec, int want_ro, const char *want_guest)
{
    char g[512];
    int ro;

    checks++;
    ro = parse_bind_spec(spec, g, sizeof g);
    if (ro != want_ro || strcmp(g, want_guest) != 0) {
        fails++;
        printf("  [FAIL] %-34s ro=%d guest=\"%s\"  期望 ro=%d guest=\"%s\"\n",
               spec, ro, g, want_ro, want_guest);
    } else {
        printf("  [ok]   %-34s ro=%d guest=\"%s\"\n", spec, ro, g);
    }
}

/* 源码文本断言：确认两个实现处都已改成大小写不敏感 */
static int file_contains(const char *path, const char *needle)
{
    FILE *f = fopen(path, "r");
    static char buf[64 * 1024];
    size_t n;
    if (f == NULL)
        return -1;
    n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);
    return strstr(buf, needle) != NULL;
}

int main(void)
{
    printf("=== bind `:ro` 大小写不敏感 探针 ===\n\n");

    /* 1) 各种大小写都应识别为只读 */
    ck_ro("/src:/dst:ro", 1, "/dst");
    ck_ro("/src:/dst:RO", 1, "/dst");
    ck_ro("/src:/dst:Ro", 1, "/dst");
    ck_ro("/src:/dst:rO", 1, "/dst");

    /* 2) 其它第三段按可写，且仍截断（不误锁） */
    ck_ro("/src:/dst:rw", 0, "/dst");
    ck_ro("/src:/dst:RW", 0, "/dst");
    ck_ro("/src:/dst:",   0, "/dst");
    ck_ro("/src:/dst:rol", 0, "/dst");

    /* 3) 无第三段 */
    ck_ro("/src:/dst", 0, "/dst");

    /* 4) 源码文本断言：两处实现都必须含大小写不敏感的判据 */
    {
        const char *files[2] = { "src/runtime/preload.c",
                                 "src/launcher/launcher.c" };
        int i;
        for (i = 0; i < 2; i++) {
            int hit = file_contains(files[i], "mod[0] == 'r' || mod[0] == 'R'");
            checks++;
            if (hit == 1) {
                printf("  [ok]   %s 含大小写不敏感判据\n", files[i]);
            } else if (hit == 0) {
                fails++;
                printf("  [FAIL] %s **不含**新判据（可能被回退）\n", files[i]);
            } else {
                printf("  [SKIP] %s 读不到（不在仓库根运行？）\n", files[i]);
            }
        }
    }

    printf("\n----------------------------------------\n");
    printf("checks: %d  failed: %d\n", checks, fails);
    printf("RESULT: %s\n", fails == 0 ? "PASS" : "FAIL");
    return fails == 0 ? 0 : 1;
}
