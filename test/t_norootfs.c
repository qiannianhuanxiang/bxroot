#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "proc.c"

int main(void){
    const char *t,*l;
    unsetenv("PROROOT_TRAMPOLINE_PATH");
    unsetenv("PROROOT_LINKER_PATH");
    unsetenv("BXROOT_ULX_PATH");
    unsetenv("BXROOT_ULX_LDSO");
    /* 模拟 PTC 清空环境：连 BXROOT_ROOTFS 也没有 */
    unsetenv("BXROOT_ROOTFS");
    unsetenv("PROROOT_ROOTFS");
    px_tramp_cfg(&t,&l);
    printf("no-rootfs: tramp=%s linker=%s\n",
           (t&&t[0])?t:"(empty)",(l&&l[0])?l:"(empty)");
    printf("RESULT: derived_without_rootfs=%d\n", (t&&t[0]&&l&&l[0])?1:0);
    return 0;
}