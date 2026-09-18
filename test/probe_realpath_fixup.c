/*
 * 8.2 修复单元测试：realpath 返回值反向翻译的源码级断言。
 *
 * 被测函数：realpath_fixup_inplace（经 strip_rootfs_prefix_inplace +
 * detranslate_binds 串联，与 getcwd_fixup 同款逻辑）。
 *
 * 为什么源码级：realpath_fixup_inplace 是 static（不导出，避免扩符号面），
 * 且本容器 LD_PRELOAD 惰性，hook 无法运行时生效。源码级 include 是唯一
 * 能在「无 interpose」环境下验证判别与改写矩阵的方式（与 probe_d3_fixup.c
 * 同一模式：BXROOT_NO_AUTORUN=1 跳过构造链，直接驱动 g_config + 纯函数）。
 *
 * 验证边界（诚实声明）：这里测的是**判别与改写逻辑**本身，含 malloc 分支
 * 的 cap 语义（SIZE_MAX / 不足容量保底）；hook 的接入点（realpath /
 * __realpath_chk / canonicalize_file_name 的调用与转发）由代码评审 +
 * 构建符号核对 + 真机回归兜底。
 *
 * 覆盖（评估报告 8.2 要求的最小集）：
 *   - 宿主 /data/rootfs-test/tmp/x.txt（rootfs=/data/rootfs-test）→ /tmp/x.txt
 *   - rootfs 根 → /
 *   - rootfs 外路径 → 原样
 *   - bind 反向映射命中（直接注入 g_config.bind_sources/bind_targets）
 *
 * 用法：sh test/RUN_REALPATH_FIXUP.sh
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* 与 probe_d3_fixup.c 同款：避开 crtbeginS 的 __dso_handle 冲突，
 * 链接期配合 -Wl,--allow-multiple-definition。 */
#define __dso_handle bxroot_internal_dso_handle
#include "../src/runtime/preload.c"

static int g_ok = 0, g_fail = 0;

/* rootfs 配置写到静态缓冲（init_config 被 NO_AUTORUN 跳过，g_config 归零） */
static char rs_buf[4096];
static void set_rootfs(const char *rootfs) {
    snprintf(rs_buf, sizeof(rs_buf), "%s", rootfs ? rootfs : "");
    g_config.rootfs = rs_buf;
}

/* 注入一对 bind（source=宿主路径，target=guest 路径），绕过环境变量 */
static void inject_bind(const char *src, const char *tgt) {
    static char *srcs[MAX_BINDS];
    static char *tgts[MAX_BINDS];
    static int n = 0;

    if (g_config.bind_sources == NULL) {
        g_config.bind_sources = srcs;
        g_config.bind_targets = tgts;
    }
    if (n >= MAX_BINDS) { g_fail++; printf("  ❌ bind 注入溢出\n"); return; }
    srcs[n] = strdup(src);
    tgts[n] = strdup(tgt);
    n++;
    g_config.bind_count = n;
}

/*
 * 原地修整断言：把 in 拷进独立缓冲（模拟调用方的栈缓冲），调
 * realpath_fixup_inplace，比较结果。
 *   expect == NULL → 期望「原样」（rc == 0 且内容未变）
 *   cap            → 传入的容量（SIZE_MAX 模拟 glibc malloc 堆缓冲分支）
 */
static void check_inplace(const char *name, const char *in, const char *expect,
                          size_t cap, const char *rootfs) {
    char out[MAX_PATH_LEN];

    set_rootfs(rootfs);
    snprintf(out, sizeof(out), "%s", in);

    int rc = realpath_fixup_inplace(out, cap);
    int pass;
    if (expect == NULL)
        pass = (rc == 0) && (strcmp(out, in) == 0);
    else
        pass = (rc == 1) && (strcmp(out, expect) == 0);

    if (pass) {
        g_ok++;
        printf("  ✅ %-30s %s\n", name, expect ? out : "(原样)");
    } else {
        g_fail++;
        printf("  ❌ %-30s rc=%d out=%s 期望 rc=%d %s\n", name, rc, out,
               expect ? 1 : 0, expect ? expect : "(原样)");
    }
}

int main(void) {
    const char *RF = "/data/rootfs-test";   /* 假想 rootfs，判别用 */

    printf("=== A. rootfs 前缀剥离（SIZE_MAX = glibc malloc 堆缓冲语义）===\n");
    check_inplace("rootfs 内文件", "/data/rootfs-test/tmp/x.txt",
                  "/tmp/x.txt", SIZE_MAX, RF);
    check_inplace("rootfs 根",     "/data/rootfs-test",
                  "/", SIZE_MAX, RF);
    check_inplace("rootfs 外路径", "/etc/passwd",
                  NULL, SIZE_MAX, RF);
    check_inplace("rootfs 外深层", "/var/log/dpkg.log",
                  NULL, SIZE_MAX, RF);
    check_inplace("前缀相似不误剥", "/data/rootfs-testX/y",
                  NULL, SIZE_MAX, RF);

    printf("=== B. bind 反向映射（注入 g_config.bind_sources/bind_targets）===\n");
    inject_bind("/mnt/host-storage", "/sdcard");
    check_inplace("bind 命中(rootfs 外)", "/mnt/host-storage/photos/1.jpg",
                  "/sdcard/photos/1.jpg", SIZE_MAX, RF);
    /* 先剥 rootfs 再反 bind 的串联顺序：剥出的路径正落在 bind source 下 */
    check_inplace("bind 命中(剥 rootfs 后)", "/data/rootfs-test/mnt/host-storage/photos/1.jpg",
                  "/sdcard/photos/1.jpg", SIZE_MAX, RF);
    check_inplace("bind 未命中走剥离",   "/data/rootfs-test/tmp/x.txt",
                  "/tmp/x.txt", SIZE_MAX, RF);
    check_inplace("bind 组件边界不误配", "/mnt/host-storageX/y",
                  NULL, SIZE_MAX, RF);

    printf("=== C. 栈缓冲 / 容量语义（resolved_path 分支）===\n");
    /* PATH_MAX 调用方缓冲：正常重写 */
    check_inplace("栈缓冲(PATH_MAX)", "/data/rootfs-test/tmp/x.txt",
                  "/tmp/x.txt", (size_t)PATH_MAX, RF);
    /* cap 放不下 bind 反查结果：保留已剥前缀的结果（rc=1），绝不越界 */
    inject_bind("/h", "/sdcard-very-long-target-name");
    check_inplace("cap 不足保剥前缀", "/data/rootfs-test/h/xyz",
                  "/h/xyz", 7, RF);
    /* 同一 bind、容量充足：正常反查 */
    check_inplace("cap 充足走 bind 反查", "/data/rootfs-test/h/xyz",
                  "/sdcard-very-long-target-name/xyz", SIZE_MAX, RF);

    printf("\n=== 结果: %d 通过 / %d 失败 ===\n", g_ok, g_fail);
    return g_fail ? 1 : 0;
}
