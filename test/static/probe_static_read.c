/* 读 /etc/bx-static-marker 并打印 —— 静态/动态两种链接各编一份，用于验证
 * 非默认 rootfs 下路径翻译是否生效（RUN_STATIC_ELF.sh）。 */
#include <stdio.h>
int main(void)
{
    char b[128] = {0};
    FILE *f = fopen("/etc/bx-static-marker", "r");
    if (f == NULL) { printf("MARKER-MISSING\n"); return 3; }
    if (fgets(b, sizeof b, f) == NULL) { printf("MARKER-EMPTY\n"); return 4; }
    printf("marker=%s", b);
    return 0;
}
