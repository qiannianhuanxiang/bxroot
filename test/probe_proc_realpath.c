/* realpath 族对 /proc 魔法链接的 guest 视角（由 RUN_PROC_VIEW.sh 驱动）。
 * 逐参数输出 realpath(arg)（失败输出 ERR<errno>）。 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
int main(int argc, char **argv)
{
    int i;
    for (i = 1; i < argc; i++) {
        char *r = realpath(argv[i], NULL);
        if (r) { printf("%s\n", r); free(r); }
        else printf("ERR%d\n", errno);
    }
    return 0;
}
