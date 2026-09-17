/* =====================================================================
 * dl 家族契约探针：`dlerror` / `dlsym` 同源 + `dl_iterate_phdr` 模块视图
 * =====================================================================
 *
 * 为什么需要它
 * ------------
 * 这两个符号的缺陷**在编译期完全看不出来**，只有真跑才有判据：
 *
 *   dlerror        —— bxroot 的 dlsym 走 linker 服务，不写 glibc 的
 *                     `__libc_dlerror_result`，于是 `dlerror()` 恒返回 NULL。
 *                     症状是"调用方拿不到错误原因，真故障被静默吞掉"。
 *   dl_iterate_phdr—— 不导出时客户程序解析到 glibc 那份，而它只认识主程序，
 *                     模块视图从 N 个塌成 1 个。
 *
 * 判据（每条都必须是**行为**，不是"符号在不在"）
 * ---------------------------------------------
 *   A1 初始 dlerror() 为 NULL
 *   A2 失败的 dlsym 之后 dlerror() **非空**，且串里含符号名
 *   A3 dlerror() **读一次即清**：第二次必须是 NULL
 *   A4 成功的 dlsym 不产生错误
 *   A5 带句柄的 dlsym 失败也要留痕（官方用另一条格式串）
 *   B  反复"失败 dlsym + dlerror"不崩 —— 这是**自递归防护**的判据：
 *      任何"薄转发给 libc"的写法都会解析回本库自己 → 无限自递归 → SIGSEGV
 *   C  dlopen 不存在的库返回 NULL 后 dlerror() 可读且进程存活
 *   D  dl_iterate_phdr 的模块视图**必须包含实现 dlsym 的那个库**
 *      —— 这一条正是"两符号必须一起修"的粘合点：只有视图完整，
 *      自递归检测垫片才拿得到自身基址（修前 `base=0x0`，垫片失效）
 *   E  dl_iterate_phdr 允许**合法嵌套**（回调用再遍历），不许误伤
 *
 * 退出码：0 = 全部通过；1 = 有失败（逐条打印 PASS/FAIL）
 * ===================================================================== */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <link.h>

static int g_fail = 0;

static void ok(const char *name, int cond, const char *detail) {
    printf("  %s %-46s %s\n", cond ? "PASS" : "FAIL", name,
           detail ? detail : "");
    if (!cond)
        g_fail++;
}

/* ---- dl_iterate_phdr 收集 ---- */
#define MAXMOD 128
static char          g_mods[MAXMOD][512];
static unsigned long g_base[MAXMOD];
static int           g_nmod;

static int collect_cb(struct dl_phdr_info *i, size_t s, void *d) {
    (void)s; (void)d;
    if (i->dlpi_name && i->dlpi_name[0] && g_nmod < MAXMOD) {
        strncpy(g_mods[g_nmod], i->dlpi_name, sizeof g_mods[0] - 1);
        g_base[g_nmod] = (unsigned long)i->dlpi_addr;
        g_nmod++;
    }
    return 0;
}

/* ---- 合法嵌套：全局深度计数，到 2 层就停 ---- */
static _Thread_local int g_depth;
static int g_nest_ok;

static int nest_cb(struct dl_phdr_info *i, size_t s, void *d) {
    int *n = d; (void)i; (void)s;
    (*n)++;
    if (g_depth < 2) {
        int inner = 0;
        g_depth++;
        int rc = dl_iterate_phdr(nest_cb, &inner);
        g_depth--;
        if (rc == 0 && inner > 0)
            g_nest_ok++;
    }
    return 0;
}

int main(void) {
    char buf[512];

    printf("== dl 家族契约（dlerror / dlsym / dl_iterate_phdr）==\n");

    /* ---------- A) dlerror 契约 ---------- */
    printf("\n[A] dlerror 契约\n");

    ok("A1 初始 dlerror() 为 NULL", dlerror() == NULL, NULL);

    void *p = dlsym(RTLD_DEFAULT, "bxroot_definitely_no_such_symbol_42");
    const char *e1 = dlerror();
    snprintf(buf, sizeof buf, "p=%p dlerror=<%s>", p, e1 ? e1 : "NULL");
    ok("A2 失败 dlsym 后 dlerror 非空", p == NULL && e1 != NULL, buf);
    ok("A2b 错误串含符号名",
       e1 != NULL && strstr(e1, "bxroot_definitely_no_such_symbol_42") != NULL,
       NULL);

    const char *e2 = dlerror();
    ok("A3 读一次即清（第二次为 NULL）", e2 == NULL, NULL);

    void *q = dlsym(RTLD_DEFAULT, "malloc");
    ok("A4 成功的 dlsym 不产生错误",
       q != NULL && dlerror() == NULL, NULL);

    /* 带句柄失败：官方用另一条格式串 */
    void *hl = dlopen("libm.so.6", RTLD_NOW | RTLD_GLOBAL);
    if (hl != NULL) {
        void *bad = dlsym(hl, "no_such_symbol_in_libm_xyz");
        const char *eh = dlerror();
        snprintf(buf, sizeof buf, "<%s>", eh ? eh : "NULL");
        ok("A5 带句柄失败也留痕", bad == NULL && eh != NULL, buf);
    } else {
        ok("A5 带句柄失败也留痕", 0, "无法 dlopen libm.so.6（环境问题）");
    }

    /* ---------- B) 自递归防护 ---------- */
    printf("\n[B] 自递归防护（薄转发会在此无限递归 → SIGSEGV）\n");
    {
        int i, bad = 0;
        for (i = 0; i < 3000; i++) {
            void *r = dlsym(RTLD_DEFAULT, "bxroot_no_such_symbol_stress");
            const char *e = dlerror();
            if (r != NULL || e == NULL || dlerror() != NULL) { bad = i + 1; break; }
        }
        if (bad)
            snprintf(buf, sizeof buf, "第 %d 轮出错", bad);
        else
            snprintf(buf, sizeof buf, "3000 轮全部正确");
        ok("B1 3000 轮失败 dlsym+dlerror 不崩", bad == 0, buf);
    }

    /* ---------- C) dlopen 失败不许崩 ---------- */
    printf("\n[C] dlopen 失败路径\n");
    {
        int i, bad = 0;
        for (i = 0; i < 200; i++) {
            void *h = dlopen("/nonexistent/__bxroot_absent__.so", RTLD_NOW);
            if (h != NULL) { bad = 1; break; }
            dlerror();
        }
        ok("C1 200 轮 dlopen 失败不崩", bad == 0, NULL);
    }

    /* ---------- D) dl_iterate_phdr 模块视图（与 dlsym 归属互证） ---------- */
    printf("\n[D] dl_iterate_phdr 模块视图\n");
    {
        Dl_info di;
        int got, found = 0;
        unsigned long foundbase = 0;

        memset(&di, 0, sizeof di);
        got = dladdr((void *)(uintptr_t)&dlsym, &di);

        g_nmod = 0;
        dl_iterate_phdr(collect_cb, NULL);

        snprintf(buf, sizeof buf, "视图 %d 个已命名模块", g_nmod);
        ok("D1 模块视图 > 1（不是只有主程序）", g_nmod > 1, buf);

        if (got && di.dli_fname) {
            int i;
            for (i = 0; i < g_nmod; i++)
                if (strcmp(g_mods[i], di.dli_fname) == 0) {
                    found = 1;
                    foundbase = g_base[i];
                }
        }
        snprintf(buf, sizeof buf, "%s base=0x%lx",
                 found ? di.dli_fname : "(未找到)", foundbase);
        ok("D2 视图含实现 dlsym 的那个库", found && foundbase != 0, buf);

        snprintf(buf, sizeof buf, "dladdr(&main) fname=%s",
                 di.dli_fname ? di.dli_fname : "(null)");
        ok("D3 dladdr(&dlsym) 有 fname/fbase",
           got == 1 && di.dli_fname != NULL && di.dli_fbase != NULL, buf);
    }

    /* ---------- E) 合法嵌套不许误伤 ---------- */
    printf("\n[E] dl_iterate_phdr 合法嵌套\n");
    {
        int n = 0, rc;
        g_depth = 0;
        g_nest_ok = 0;
        rc = dl_iterate_phdr(nest_cb, &n);
        snprintf(buf, sizeof buf, "rc=%d 外层 %d 轮，嵌套成功 %d 次",
                 rc, n, g_nest_ok);
        ok("E1 嵌套调用可用且不爆栈", rc == 0 && n > 0, buf);
    }

    printf("\n== 结果：%s（失败 %d 条）==\n",
           g_fail == 0 ? "全部通过" : "有失败", g_fail);
    fflush(stdout);
    return g_fail == 0 ? 0 : 1;
}
