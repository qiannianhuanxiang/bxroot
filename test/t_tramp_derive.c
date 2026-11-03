#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proc.c"

int main(void) {
    const char *t, *l;
    unsetenv("PROROOT_TRAMPOLINE_PATH");
    unsetenv("PROROOT_LINKER_PATH");
    unsetenv("BXROOT_ULX_PATH");
    unsetenv("BXROOT_ULX_LDSO");
    setenv("BXROOT_ROOTFS", "/tmp/miniroot", 1);
    px_tramp_cfg(&t, &l);
    int ok = (t && t[0] && l && l[0]);
    printf("derived tramp  = %s\n", (t && t[0]) ? t : "(empty)");
    printf("derived linker = %s\n", (l && l[0]) ? l : "(empty)");
    if (ok) {
        printf("tramp  X_OK: %d\n", access(t, X_OK) == 0);
        printf("linker R_OK: %d\n", access(l, R_OK) == 0);
        /* 关键断言：推导出的两个路径都必须真实可用 */
        ok = (access(t, X_OK) == 0) && (access(l, R_OK) == 0);
    }
    printf("RESULT: derived_usable=%d\n", ok);
    return ok ? 0 : 1;
}