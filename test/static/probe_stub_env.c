/* 静态链接后走 stub-loader。打印 PROROOT_STUB_ROOTFS / PROROOT_CFG_FD
 * 是否出现在最终 env 里，用来钉住「有 CFG blob 时不注入 STUB_ROOTFS」。 */
#include <stdio.h>
#include <stdlib.h>

static void show(const char *k)
{
    const char *v = getenv(k);
    if (v == NULL || v[0] == '\0')
        printf("%s=EMPTY\n", k);
    else
        printf("%s=SET\n", k);
}

int main(void)
{
    show("PROROOT_STUB_ROOTFS");
    show("PROROOT_CFG_FD");
    return 0;
}
