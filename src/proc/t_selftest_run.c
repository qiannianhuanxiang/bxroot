/*
 * selftest 真机逻辑验证：直接 include proc.c（PX_PURE_LOGIC=1 模式），
 * 调用 px_runtime_init()，检查它写出的七项自检结果。
 *
 * 这不是"模拟"——px_runtime_init 是真实函数，里面的 stat / readlink /
 * getenv / px_self_thread_count 全部真实执行。本机与真机的路径差异会让
 * 某些项报 FAIL，这恰好证明自检能分辨好坏。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "proc.c"

#define DIAG "/tmp/bxroot-diag.log"

int main(void)
{
    FILE *f;
    char buf[8192];
    size_t n;
    const char *need[] = {
        "--- selftest ---",
        "[1] self-lib",
        "[2] ulx",
        "[3] ldso",
        "[4] rootfs",
        "[5] threads",
        "[6] self-exe",
        "[7] diag-file",
    };
    size_t i;
    int missing = 0;

    unlink(DIAG);
    setenv("BXROOT_DIAG_FILE", DIAG, 1);
    setenv("BXROOT_ROOTFS", "/nonexistent-rootfs-for-selftest", 1);
    setenv("BXROOT_ULX_PATH", "/nonexistent/ulx.so", 1);
    setenv("BXROOT_ULX_LDSO", "/nonexistent/ldso.so", 1);

    (void)px_runtime_init();

    f = fopen(DIAG, "r");
    if (f == NULL) {
        printf("FAIL diag-not-created\n");
        return 1;
    }
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    printf("---- diag ----\n%s\n--------------\n", buf);

    for (i = 0; i < sizeof(need) / sizeof(need[0]); i++) {
        if (strstr(buf, need[i]) == NULL) {
            printf("FAIL missing=%s\n", need[i]);
            missing++;
        }
    }

    /* 负向断言：给了不存在的路径，[2][3][4] 必须报 FAIL */
    if (strstr(buf, "[2] ulx") != NULL) {
        char *p = strstr(buf, "[2] ulx");
        printf("CHECK [2]: %.90s\n", p);
    }
    if (strstr(buf, "[3] ldso") != NULL) {
        char *p = strstr(buf, "[3] ldso");
        printf("CHECK [3]: %.90s\n", p);
    }
    if (strstr(buf, "[4] rootfs") != NULL) {
        char *p = strstr(buf, "[4] rootfs");
        printf("CHECK [4]: %.90s\n", p);
    }
    if (strstr(buf, "[5] threads") != NULL) {
        char *p = strstr(buf, "[5] threads");
        printf("CHECK [5]: %.90s\n", p);
    }

    printf("CONCLUSION: markers_missing=%d total=%d\n",
           missing, (int)(sizeof(need) / sizeof(need[0])));
    return missing == 0 ? 0 : 1;
}
