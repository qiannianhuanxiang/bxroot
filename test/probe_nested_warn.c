/*
 * 源码级单元：warn_stale_proroot_env 的嵌套容器排除判别。
 *
 * 背景（真实回归）：bxroot 的主要部署形态之一是跑在另一个 proroot
 * 容器里，外层会注入整套 PROROOT_* 变量。若防呆警告不排除这种正常
 * 形态，每次嵌套启动都会误报 —— 实测导致上游套件自检失败。
 *
 * 本探针用两个独立子进程分别验证两种情形（函数内有 static 打点，
 * 同一进程无法重置，故必须分进程）。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_fired = 0;
#define fprintf(stream, ...) (g_fired++, 0)
#define __dso_handle bxroot_internal_dso_handle
#include "../src/runtime/preload.c"
#undef fprintf

int main(int argc, char **argv) {
    const char *mode = (argc > 1) ? argv[1] : "nested";

    if (strcmp(mode, "nested") == 0) {
        /* 嵌套容器：有实现变量 + PROROOT_ROOTFS → 期望无警告 */
        setenv("PROROOT_CFG_FD", "/x/cfg", 1);
        setenv("PROROOT_ROOTFS", "/outer/rootfs", 1);
        unsetenv("BXROOT_ROOTFS");
        warn_stale_proroot_env();
        printf("nested  warning=%d expect=0 %s\n", g_fired, g_fired == 0 ? "OK" : "FAIL");
        return g_fired == 0 ? 0 : 1;
    }

    /* 用户手滑：只有 PROROOT_ROOTFS，无任何实现变量 → 期望报警 */
    {
        /* 清掉所有实现变量与 BXROOT_ 对应项 */
        const char *kill[] = { "PROROOT_CFG_FD", "PROROOT_ESCAPE_FD",
            "PROROOT_TRAMPOLINE_PATH", "PROROOT_STUB_LOADER",
            "PROROOT_LINKER_PATH", "PROROOT_SIGSYS_LOG_HOST_PATH",
            "BXROOT_ROOTFS", NULL };
        for (int i = 0; kill[i]; i++) unsetenv(kill[i]);
        setenv("PROROOT_ROOTFS", "/user/typo", 1);
        /* 注意：外层 proroot 会在 exec 时重注入实现变量，所以本模式
         * 只在"非嵌套环境"下有意义 —— 见 RUN_NESTED_WARN.sh 的说明。 */
    }
    warn_stale_proroot_env();
    printf("typo    warning=%d expect=1 %s\n", g_fired, g_fired == 1 ? "OK" : "FAIL");
    return g_fired == 1 ? 0 : 1;
}
