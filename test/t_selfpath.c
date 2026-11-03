#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proc.c"

int main(void) {
    char buf[PX_PATH_MAX];
    /* 清空所有相关环境变量 */
    unsetenv("PROROOT_LIB_PATH");
    unsetenv("BXROOT_LD_PRELOAD");
    unsetenv("BXROOT_ULX_PATH");
    unsetenv("BXROOT_ULX_LDSO");
    unsetenv("PROROOT_TRAMPOLINE_PATH");
    unsetenv("PROROOT_LINKER_PATH");

    int ok = px_self_lib_path(buf, sizeof(buf));
    printf("px_self_lib_path -> %d\n", ok);
    printf("  path = %s\n", ok ? buf : "(none)");
    if (ok) {
        printf("  readable: %d\n", access(buf, R_OK) == 0);
    }

    /* 三档回落：环境全空 + rootfs → 应当推导出 tramp/linker */
    {
        const char *t, *l;
        setenv("BXROOT_ROOTFS", "/tmp/miniroot", 1);
        px_tramp_cfg(&t, &l);
        printf("tramp_cfg derived: tramp=%s\n", (t && t[0]) ? t : "(empty)");
        printf("tramp_cfg derived: linker=%s\n", (l && l[0]) ? l : "(empty)");
    }
    return ok ? 0 : 1;
}