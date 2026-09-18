/*
 * D3 单元测试：readlink_fixup / strip_rootfs_prefix_inplace 的源码级断言。
 *
 * 为什么源码级：readlink_fixup 是 static（不导出，避免扩符号面），而本
 * 容器 LD_PRELOAD 惰性 + bridge 链 SIGILL，hook 无法运行时生效。源码级
 * include 是唯一能在「无 interpose」环境下验证判别矩阵的方式。
 *
 * 验证边界（诚实声明）：这里测的是**判别与改写逻辑**本身；hook 的接入
 * （readlink/readlinkat 调用点）与截断语义由代码评审 + 真机回归兜底。
 *
 * 用法：sh test/RUN_D3_FIXUP.sh
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 跳过与宿主的 main 冲突：preload.c 无 main；需先杀 constructor 影响 ——
 * constructor 在库加载时才跑，静态编译到可执行文件里会在 main 前执行。
 * init_config 等在无环境变量下是安全的（g_config 归零路径），实测可行。
 *
 * preload.c 自带 __dso_handle（供 D4/proc.c 桥接），静态编译时会与
 * crtbeginS 的冲突 —— 这里换成静态对象文件再链，或者直接用 -Wl,--allow-
 * multiple-definition。见 RUN_D3_FIXUP.sh。 */
#define __dso_handle bxroot_internal_dso_handle
#include "../src/runtime/preload.c"

static int g_ok = 0, g_fail = 0;

static void check(const char *name, const char *in, const char *expect,
                  int expect_rc, const char *rootfs) {
    char out[MAX_PATH_LEN];
    /* 设定被测 rootfs（init_config 已在 constructor 跑过，直接改 g_config） */
    static char rs_buf[4096];
    snprintf(rs_buf, sizeof(rs_buf), "%s", rootfs ? rootfs : "");
    g_config.rootfs = rs_buf;

    int rc = readlink_fixup(in, out, sizeof(out));
    int pass = (rc == expect_rc) &&
               (expect_rc == 0 || strcmp(out, expect) == 0);
    if (pass) { g_ok++; printf("  ✅ %-28s %s\n", name, expect_rc ? out : "(原样)"); }
    else      { g_fail++; printf("  ❌ %-28s rc=%d out=%s 期望 rc=%d %s\n",
                                 name, rc, out, expect_rc,
                                 expect_rc ? expect : "(原样)"); }
}

int main(void) {
    const char *RF = "/data/rootfs-test";   /* 假想 rootfs，判别用 */

    printf("=== 规则 1：内核契约格式绝不能动 ===\n");
    check("socket:[12345]", "socket:[12345]", NULL, 0, RF);
    check("pipe:[777]",     "pipe:[777]",     NULL, 0, RF);
    check("anon_inode:[eventfd]", "anon_inode:[eventfd]", NULL, 0, RF);

    printf("=== 规则 2：/proc/<pid>/root 系 ===\n");
    check("/proc/self/root", "/proc/self/root", "/", 1, RF);
    check("/proc/1234/root", "/proc/1234/root", "/", 1, RF);

    printf("=== 规则 3：宿主路径反向翻译（rootfs=%s）===\n", RF);
    check("rootfs 内文件",   "/data/rootfs-test/tmp/x.txt", "/tmp/x.txt", 1, RF);
    check("rootfs 根",       "/data/rootfs-test",           "/",          1, RF);
    check("rootfs 前缀相似", "/data/rootfs-testX/y",        NULL,         0, RF);
    check("rootfs 外路径",   "/etc/passwd",                 NULL,         0, RF);
    check("rootfs 内 cwd",   "/data/rootfs-test/root/w",    "/root/w",    1, RF);

    printf("=== 规则 4：rootfs 祖先目录 → guest 视角 /（上游 test-51943658）===\n");
    /*
     * 场景来源：openat(open("/"), "..") 的 fd 在内核里解析为 $ROOTFS 的
     * 父目录，readlink 返回不含 rootfs 前缀的宿主路径。上游断言必须是 "/"。
     * rootfs = /data/rootfs-test 的祖先链只有 "/" 与 "/data"。
     */
    check("rootfs 的直接父",  "/data",            "/", 1, RF);
    check("祖先链更上级",     "/",                "/", 1, RF);
    /* 边界：不在祖先链上的路径不得被改成 / */
    check("非祖先（同前缀）", "/data/rootfs-testX", NULL, 0, RF);
    check("非祖先（兄弟）",   "/data/other",       NULL, 0, RF);
    check("非祖先（无关）",   "/etc/passwd",       NULL, 0, RF);

    printf("=== 组件边界（不得误剥）===\n");
    /* /data/rootfs-test 不是 /data/rootfs-test 的路径 —— 前缀相似已覆盖 */

    printf("\n=== 结果: %d 通过 / %d 失败 ===\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
