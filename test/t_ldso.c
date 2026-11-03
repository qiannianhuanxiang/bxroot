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
    printf("tramp  = %s\n", (t && t[0]) ? t : "(empty)");
    printf("linker = %s\n", (l && l[0]) ? l : "(empty)");
    if (l && l[0]) printf("linker R_OK = %d\n", access(l, R_OK) == 0);
    return 0;
}