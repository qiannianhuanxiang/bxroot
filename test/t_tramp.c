#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc.c"

int main(void) {
    const char *t1, *l1, *t2, *l2;

    /* case 1: 环境有 PROROOT_* → 优先用它 */
    setenv("PROROOT_TRAMPOLINE_PATH", "/outer/bridge.so", 1);
    setenv("PROROOT_LINKER_PATH", "/outer/linker.so", 1);
    px_tramp_cfg(&t1, &l1);
    printf("env-proroot    : tramp=%s linker=%s\n", t1 ? t1 : "(null)", l1 ? l1 : "(null)");

    /* case 2: 只有 BXROOT_ULX_*（无 PROROOT）→ 用它 */
    unsetenv("PROROOT_TRAMPOLINE_PATH");
    unsetenv("PROROOT_LINKER_PATH");
    setenv("BXROOT_ULX_PATH", "/env/ulx.so", 1);
    setenv("BXROOT_ULX_LDSO", "/env/ld.so", 1);
    px_tramp_cfg(&t2, &l2);
    printf("env-bxroot     : tramp=%s linker=%s\n", t2 ? t2 : "(null)", l2 ? l2 : "(null)");

    /* case 3: 全空 + 有 rootfs → 应当由 dladdr 推导（但需文件真实存在才采信） */
    unsetenv("BXROOT_ULX_PATH");
    unsetenv("BXROOT_ULX_LDSO");
    setenv("BXROOT_ROOTFS", "/tmp/miniroot", 1);
    {
        const char *t3, *l3;
        px_tramp_cfg(&t3, &l3);
        printf("derived        : tramp=%s linker=%s\n",
               t3 && t3[0] ? t3 : "(null/empty)",
               l3 && l3[0] ? l3 : "(null/empty)");
    }
    return 0;
}